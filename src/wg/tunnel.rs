//! The boringtun WireGuard tunnel — a single peer (the inference backend).
//!
//! Wraps one boringtun [`Tunn`] plus the real UDP socket that carries the
//! encrypted traffic. Three operations drive it, all called from the event
//! loop in `forward.rs`:
//! - [`send`](Tunnel::send): encrypt an outbound inner IP packet (from smoltcp)
//!   and write the WireGuard datagram to the peer.
//! - [`recv`](Tunnel::recv): read one UDP datagram, decrypt it, and return the
//!   inner IP packet for smoltcp (handshake/cookie traffic is handled here and
//!   produces no inner packet).
//! - [`update_timers`](Tunnel::update_timers): drive handshakes, keepalive and
//!   rekey on a periodic tick. Skipping this silently kills the tunnel.
//!
//! Adapted from `tokio-wireguard`'s `interface/tunnel.rs`
//! (github.com/raftario/river, MIT OR Apache-2.0), trimmed from its general
//! multi-peer responder to a single-peer client: no peer table, no
//! `parse_incoming_packet`/`RateLimiter` (`decapsulate` routes to our one
//! tunnel and we pass `rate_limiter: None` as a pure initiator). Ported to
//! boringtun 0.7.1, whose `Tunn::new` returns `Self` rather than a `Result`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;

/// Max UDP datagram we might send or receive. WireGuard data packets are
/// MTU-sized, but this stays generous so handshake/cookie and any datagram fit.
const MAX_PACKET: usize = u16::MAX as usize;

/// Our local sender index in WireGuard packets. With a single tunnel there is
/// nothing to demultiplex, so a fixed value is fine.
const LOCAL_INDEX: u32 = 0;

pub struct Tunnel {
    tunn: Tunn,
    /// Fixed peer endpoint — this side is the client, so it never roams.
    endpoint: SocketAddr,
    socket: UdpSocket,
    /// Incoming UDP datagrams.
    recv_buf: Vec<u8>,
    /// Decrypted inner IP packets (the `decapsulate` destination).
    decap_buf: Vec<u8>,
    /// Outbound WireGuard datagrams (the `encapsulate`/`update_timers`/drain
    /// destination). Distinct from `decap_buf` so the `recv` drain loop can
    /// re-borrow a buffer without aliasing the packet it is currently sending.
    net_buf: Vec<u8>,
}

impl Tunnel {
    /// Build the tunnel and bind an ephemeral local UDP port. The handshake is
    /// performed lazily by boringtun on the first `send`/timer tick.
    pub async fn new(
        private_key: StaticSecret,
        peer_public_key: PublicKey,
        endpoint: SocketAddr,
        persistent_keepalive: Option<u16>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        let tunn = Tunn::new(
            private_key,
            peer_public_key,
            None, // preshared key — not used
            persistent_keepalive,
            LOCAL_INDEX,
            None, // rate limiter — responder-side only; we are the initiator
        );
        Ok(Self {
            tunn,
            endpoint,
            socket,
            recv_buf: vec![0u8; MAX_PACKET],
            decap_buf: vec![0u8; MAX_PACKET],
            net_buf: vec![0u8; MAX_PACKET],
        })
    }

    /// Encrypt one inner IP packet and send the resulting WireGuard datagram.
    pub async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        let Self { tunn, socket, endpoint, net_buf, .. } = self;
        match tunn.encapsulate(packet, net_buf) {
            TunnResult::WriteToNetwork(datagram) => {
                socket.send_to(datagram, *endpoint).await?;
            }
            TunnResult::Err(e) => tracing::debug!("wg encapsulate error: {e:?}"),
            // `Done` = nothing to transmit (e.g. dropped while handshaking).
            _ => {}
        }
        Ok(())
    }

    /// Read and decrypt one datagram. Returns the inner IP packet for smoltcp,
    /// or `None` when the datagram was protocol traffic (handshake/cookie) or
    /// produced nothing to forward.
    /// `Err` is distinct from `Ok(None)`: the caller treats "nothing to forward"
    /// as a normal tick and loops straight back into `recv`, so collapsing a
    /// persistent `recv_from` failure into `None` (as `.ok()?` did) spins that
    /// loop at full tilt, burning CPU and never surfacing the fault.
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Self { tunn, socket, endpoint, recv_buf, decap_buf, net_buf } = self;

        let (len, _src) = socket.recv_from(recv_buf).await?;

        match tunn.decapsulate(None, &recv_buf[..len], decap_buf) {
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                // Copy out: returning an owned Vec keeps the borrow off `self`,
                // so the caller can use the tunnel and the device freely. One
                // small alloc per inbound packet — negligible at this scale.
                Ok(Some(packet.to_vec()))
            }
            TunnResult::WriteToNetwork(mut datagram) => {
                // Handshake/cookie response: flush it, then drain any further
                // queued packets. The drain decapsulates into `net_buf` (not
                // `decap_buf`) so the next call doesn't alias `datagram`.
                loop {
                    if let Err(e) = socket.send_to(datagram, *endpoint).await {
                        tracing::warn!("wg: send_to failed draining handshake packets: {e}");
                        break;
                    }
                    match tunn.decapsulate(None, &[], net_buf) {
                        TunnResult::WriteToNetwork(next) => datagram = next,
                        _ => break,
                    }
                }
                Ok(None)
            }
            TunnResult::Done | TunnResult::Err(_) => Ok(None),
        }
    }

    /// Drive handshakes, persistent keepalive and rekeying. Call on a periodic
    /// tick (~every 100–250 ms); without it the tunnel goes silent and dies.
    pub async fn update_timers(&mut self) -> io::Result<()> {
        let Self { tunn, socket, endpoint, net_buf, .. } = self;
        match tunn.update_timers(net_buf) {
            TunnResult::WriteToNetwork(datagram) => {
                socket.send_to(datagram, *endpoint).await?;
            }
            // e.g. ConnectionExpired after too many failed handshakes. boringtun
            // is meant to re-handshake on the next activity, but a wedged session
            // may not — the forwarder's watchdog bounces the tunnel if the
            // handshake stays stale (see `last_handshake_age` + self-heal).
            TunnResult::Err(e) => tracing::warn!("wg timer event: {e:?}"),
            _ => {}
        }
        Ok(())
    }

    /// Time since the last completed WireGuard handshake, or `None` if none has
    /// completed yet. Drives both the self-heal watchdog in `forward::run` and
    /// the `/health` transport signal, so a dead tunnel is distinguishable from
    /// a dead LLM.
    pub fn last_handshake_age(&self) -> Option<Duration> {
        self.tunn.time_since_last_handshake()
    }
}
