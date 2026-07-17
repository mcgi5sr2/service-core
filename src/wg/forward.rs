//! The WireGuard forwarder — the event-loop task that ties [`Device`],
//! [`Tunnel`] and a smoltcp `Interface` together, and exposes one service
//! reachable over the tunnel (typically an inference backend) on a loopback
//! TCP port.
//!
//! Design (single stack task + minimal per-connection stream):
//! - One **stack task** ([`run`]) owns the `Interface`, the `Device` and the
//!   `Tunnel`, and a `Mutex<SocketSet>` shared with the connection streams. It
//!   pumps three things on every wake: smoltcp `poll`, outbound packets →
//!   `tunnel.send`, and inbound datagrams `tunnel.recv` → smoltcp.
//! - Each accepted loopback connection becomes a [`WgStream`] — a thin
//!   `AsyncRead`/`AsyncWrite` over one smoltcp TCP socket, using smoltcp's
//!   waker registration so reads/writes park correctly. The acceptor then just
//!   runs [`tokio::io::copy_bidirectional`] between the loopback stream and the
//!   `WgStream`, which gives correct half-close and backpressure for free.
//!
//! The `Mutex<SocketSet>` is only ever held for synchronous smoltcp calls —
//! never across an `.await` — so it cannot deadlock the runtime.
//!
//! Structure follows `tokio-wireguard` (github.com/raftario/river,
//! MIT OR Apache-2.0); the single-target loopback forwarder replaces its
//! general-purpose `TcpStream`/`TcpListener`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskCtx, Poll};
use std::time::Duration;

use anyhow::Context;
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as NetInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::interval;

use super::device::Device;
use super::tunnel::Tunnel;

/// Per-socket buffer size (each direction).
const SOCKET_BUF: usize = 64 * 1024;
/// Timer cadence for `Tunn::update_timers` (handshake/keepalive/rekey).
const TIMER_MS: u64 = 100;
/// WireGuard session lifetime (REJECT_AFTER_TIME). A completed handshake older
/// than this means the session has expired with nothing renewing it — the
/// tunnel is effectively dead. A healthy keepalive'd tunnel always rekeys well
/// inside this window, so it never crosses the line during normal operation.
const HANDSHAKE_STALE_SECS: u64 = 180;
/// How long the tunnel may stay unhealthy (stale, or never-handshook at
/// startup) before the watchdog bounces it. Doubles as the startup grace for
/// the first handshake.
const REHANDSHAKE_AFTER: Duration = Duration::from_secs(30);

/// Configuration for the WireGuard transport.
pub struct WgConfig {
    pub private_key: StaticSecret,
    pub peer_public_key: PublicKey,
    /// The peer's UDP endpoint that carries the tunnel (e.g. `172.16.50.38:51820`).
    /// Resolved once at startup; re-resolved from `endpoint_host` on self-heal.
    pub endpoint: SocketAddr,
    /// Raw `WG_ENDPOINT` value (host:port), kept for periodic re-resolution so a
    /// DDNS record that follows the box's DHCP IP is picked up without a restart.
    pub endpoint_host: String,
    /// Our address on the WireGuard network (e.g. `10.99.0.1`).
    pub address: Ipv4Addr,
    /// The target service's WireGuard address (e.g. `10.99.0.2`).
    pub target_ip: Ipv4Addr,
    /// The target service's port (e.g. `8080`).
    pub target_port: u16,
    pub persistent_keepalive: Option<u16>,
    pub mtu: usize,
}

/// Cheap, cloneable read handle onto the tunnel's handshake state. Lets `/health`
/// report the *transport* layer independently of whether the target service is
/// answering — an HTTP probe *through* the tunnel conflates "tunnel down" with
/// "service down"; this separates them.
#[derive(Clone)]
pub struct WgHealth {
    /// Secs since the last completed handshake; `u64::MAX` = none yet.
    last_handshake_secs: Arc<AtomicU64>,
}

impl WgHealth {
    fn new() -> Self {
        Self { last_handshake_secs: Arc::new(AtomicU64::new(u64::MAX)) }
    }

    /// Record the current handshake age (called each timer tick by the stack task).
    fn set(&self, age: Option<Duration>) {
        let secs = age.map(|d| d.as_secs()).unwrap_or(u64::MAX);
        self.last_handshake_secs.store(secs, Ordering::Relaxed);
    }

    /// Secs since the last completed handshake, or `None` if none has completed yet.
    pub fn last_handshake_secs(&self) -> Option<u64> {
        match self.last_handshake_secs.load(Ordering::Relaxed) {
            u64::MAX => None,
            s => Some(s),
        }
    }

    /// True when the session is live — a handshake completed within its lifetime.
    pub fn handshake_ok(&self) -> bool {
        self.last_handshake_secs().is_some_and(|s| s < HANDSHAKE_STALE_SECS)
    }
}

/// State shared between the stack task and the per-connection [`WgStream`]s.
struct Shared {
    sockets: Mutex<SocketSet<'static>>,
    /// Pings the stack task to re-poll after a stream writes or closes.
    repoll: Notify,
}

/// A request from the acceptor for the stack task to open a connected socket.
struct OpenRequest {
    resp: oneshot::Sender<SocketHandle>,
}

/// Start the forwarder: bind a loopback TCP port, spawn the stack task and the
/// acceptor, and return the loopback address to use as the plain-HTTP base for
/// the target service.
pub async fn start(cfg: WgConfig) -> io::Result<(SocketAddr, WgHealth)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let local_addr = listener.local_addr()?;

    let tunnel = Tunnel::new(
        cfg.private_key.clone(),
        cfg.peer_public_key,
        cfg.endpoint,
        cfg.persistent_keepalive,
    )
    .await?;

    let shared = Arc::new(Shared {
        sockets: Mutex::new(SocketSet::new(Vec::new())),
        repoll: Notify::new(),
    });

    let health = WgHealth::new();
    let (open_tx, open_rx) = mpsc::unbounded_channel::<OpenRequest>();
    tokio::spawn(acceptor(listener, open_tx, shared.clone()));
    tokio::spawn(run(cfg, tunnel, shared, open_rx, health.clone()));

    Ok((local_addr, health))
}

/// The stack task: drives smoltcp + the tunnel, and opens sockets on request.
async fn run(
    cfg: WgConfig,
    mut tunnel: Tunnel,
    shared: Arc<Shared>,
    mut open_rx: mpsc::UnboundedReceiver<OpenRequest>,
    health: WgHealth,
) {
    let mut device = Device::new(cfg.mtu);
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        NetInstant::now(),
    );
    iface.update_ip_addrs(|addrs| {
        // /24 so the inference peer is on-link in smoltcp's view (no route table
        // needed). This is purely smoltcp-internal; the WireGuard allowed-ips
        // remain /32 in the tunnel config.
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(cfg.address), 24));
    });

    let target = IpEndpoint::new(IpAddress::Ipv4(cfg.target_ip), cfg.target_port);
    let mut handles: Vec<SocketHandle> = Vec::new();
    let mut next_port: u16 = 49152;
    let mut timer = interval(Duration::from_millis(TIMER_MS));
    // Wall-clock marker for the self-heal watchdog: the last time the handshake
    // was fresh (or the tunnel was (re)built). If it stays stale longer than
    // `REHANDSHAKE_AFTER`, the tunnel is bounced. Starting it at "now" gives the
    // first handshake its startup grace.
    let mut last_healthy = tokio::time::Instant::now();

    loop {
        let now = NetInstant::now();

        // 1. Advance smoltcp and reap any sockets that have fully closed.
        {
            let mut sockets = shared.sockets.lock().unwrap();
            iface.poll(now, &mut device, &mut sockets);
            handles.retain(|&h| {
                if sockets.get_mut::<tcp::Socket>(h).state() == tcp::State::Closed {
                    sockets.remove(h);
                    false
                } else {
                    true
                }
            });
        }

        // 2. Encrypt and send everything smoltcp queued for transmission. Copy
        //    out of the device first so the UDP sends happen without the lock.
        let mut outgoing: Vec<Vec<u8>> = Vec::new();
        while let Some(pkt) = device.dequeue_sent() {
            outgoing.push(pkt.to_vec());
        }
        for pkt in &outgoing {
            if let Err(e) = tunnel.send(pkt).await {
                tracing::warn!("wg: tunnel send failed, dropping outgoing packet(s): {e}");
                break;
            }
        }

        // 3. Sleep until smoltcp next needs servicing (or something wakes us).
        let delay = {
            let sockets = shared.sockets.lock().unwrap();
            iface.poll_delay(now, &sockets)
        };
        let sleep = delay
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or_else(|| Duration::from_secs(1));

        tokio::select! {
            biased;
            // A new connection to open and connect over the tunnel.
            req = open_rx.recv() => {
                if let Some(req) = req {
                    let mut sockets = shared.sockets.lock().unwrap();
                    let rx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
                    let tx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
                    let mut sock = tcp::Socket::new(rx, tx);
                    let local_port = next_port;
                    next_port = next_port.checked_add(1).unwrap_or(49152);
                    match sock.connect(iface.context(), target, local_port) {
                        Ok(()) => {
                            let handle = sockets.add(sock);
                            handles.push(handle);
                            let _ = req.resp.send(handle);
                        }
                        Err(e) => tracing::warn!("wg connect failed: {e:?}"),
                    }
                }
            }
            // An inbound (decrypted) IP packet for smoltcp.
            inner = tunnel.recv() => {
                match inner {
                    Ok(Some(packet)) => device.enqueue_received(&packet),
                    // Protocol traffic (handshake/cookie) — nothing to forward.
                    Ok(None) => {}
                    // The socket itself failed. Left alone this arm is re-polled
                    // immediately, so a persistent error would spin the loop;
                    // bounce the tunnel through the same path the handshake
                    // watchdog uses, and back off if the rebuild also fails so a
                    // dead network can't turn into a hot loop either.
                    Err(e) => {
                        tracing::error!("wg: tunnel recv failed: {e}; bouncing tunnel");
                        match rebuild_tunnel(&cfg).await {
                            Ok(fresh) => {
                                tunnel = fresh;
                                last_healthy = tokio::time::Instant::now();
                            }
                            Err(e) => {
                                tracing::error!("wg tunnel rebuild failed: {e}");
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
            }
            // Periodic WireGuard timers (handshake/keepalive/rekey) + the
            // handshake watchdog: publish the current handshake age for `/health`,
            // and if it has been stale (or never established) for too long, bounce
            // the tunnel — re-resolving the endpoint so a new box IP behind the
            // DDNS name is picked up without a pod restart. The watchdog keys on
            // handshake liveness, not request duration, so it never fires on a
            // healthy in-flight request (keepalive keeps a silent connection fresh).
            _ = timer.tick() => {
                if let Err(e) = tunnel.update_timers().await {
                    tracing::warn!("wg: update_timers failed: {e}");
                }
                let age = tunnel.last_handshake_age();
                health.set(age);
                if matches!(age, Some(d) if d.as_secs() < HANDSHAKE_STALE_SECS) {
                    last_healthy = tokio::time::Instant::now();
                } else if last_healthy.elapsed() > REHANDSHAKE_AFTER {
                    tracing::warn!(
                        last_handshake_secs = ?age.map(|d| d.as_secs()),
                        "wg handshake stale; bouncing tunnel (re-resolving endpoint)"
                    );
                    match rebuild_tunnel(&cfg).await {
                        Ok(fresh) => {
                            tunnel = fresh;
                            last_healthy = tokio::time::Instant::now();
                        }
                        Err(e) => tracing::error!("wg tunnel rebuild failed: {e}"),
                    }
                }
            }
            // A stream wrote/closed — re-poll to push its data out.
            _ = shared.repoll.notified() => {}
            // smoltcp's own deadline (retransmits etc.).
            _ = tokio::time::sleep(sleep) => {}
        }
    }
}

/// Accept loopback connections and bridge each to a tunnel socket.
async fn acceptor(
    listener: TcpListener,
    open_tx: mpsc::UnboundedSender<OpenRequest>,
    shared: Arc<Shared>,
) {
    loop {
        let mut local = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!("wg loopback accept error: {e}");
                continue;
            }
        };

        let (tx, rx) = oneshot::channel();
        if open_tx.send(OpenRequest { resp: tx }).is_err() {
            return; // stack task is gone
        }
        let handle = match rx.await {
            Ok(h) => h,
            Err(_) => continue, // connect failed; drop the loopback connection
        };

        let shared = shared.clone();
        tokio::spawn(async move {
            let mut wg = WgStream { shared, handle };
            // Pumps both directions; shuts `wg` down (→ socket.close()) on EOF.
            let _ = tokio::io::copy_bidirectional(&mut local, &mut wg).await;
        });
    }
}

/// An `AsyncRead`/`AsyncWrite` view over one smoltcp TCP socket. Reads and
/// writes park on the socket's smoltcp waker; every write/close pings the stack
/// task to re-poll so the bytes actually move.
struct WgStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
}

impl AsyncRead for WgStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut sockets = self.shared.sockets.lock().unwrap();
        let sock = sockets.get_mut::<tcp::Socket>(self.handle);
        if sock.can_recv() {
            let unfilled = buf.initialize_unfilled();
            if let Ok(n) = sock.recv_slice(unfilled) {
                buf.advance(n);
            }
            drop(sockets);
            self.shared.repoll.notify_one();
            Poll::Ready(Ok(()))
        } else if sock.may_recv()
            || matches!(sock.state(), tcp::State::SynSent | tcp::State::SynReceived)
        {
            // Either established and awaiting data, or still completing the
            // handshake — park on the recv waker, don't EOF. smoltcp's
            // `may_recv()` is false *both* while connecting and once closed;
            // only the latter is a real end-of-stream.
            sock.register_recv_waker(cx.waker());
            Poll::Pending
        } else {
            // Remote closed and nothing left buffered → EOF (empty buffer).
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for WgStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut sockets = self.shared.sockets.lock().unwrap();
        let sock = sockets.get_mut::<tcp::Socket>(self.handle);
        // Still completing the handshake — wait for the connection to establish
        // rather than treating it as a closed pipe.
        if matches!(sock.state(), tcp::State::SynSent | tcp::State::SynReceived) {
            sock.register_send_waker(cx.waker());
            return Poll::Pending;
        }
        if !sock.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wg socket closed",
            )));
        }
        if sock.can_send() {
            match sock.send_slice(data) {
                Ok(n) => {
                    drop(sockets);
                    self.shared.repoll.notify_one();
                    Poll::Ready(Ok(n))
                }
                Err(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "wg send failed",
                ))),
            }
        } else {
            sock.register_send_waker(cx.waker());
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        // smoltcp transmits as soon as it can; nothing extra to flush here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        let mut sockets = self.shared.sockets.lock().unwrap();
        sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(sockets);
        self.shared.repoll.notify_one();
        Poll::Ready(Ok(()))
    }
}

/// Resolve the peer endpoint (host:port). A DNS name re-resolves to the box's
/// current IP; a literal IP resolves to itself. Async, so it never blocks the
/// stack task's runtime thread (unlike the startup `to_socket_addrs`).
async fn resolve_endpoint(host: &str) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host(host)
        .await?
        .next()
        .with_context(|| format!("WG_ENDPOINT resolved to no addresses: {host}"))
}

/// Bounce the tunnel: re-resolve the endpoint (picks up a new box IP behind a
/// DDNS name) and hand back a fresh boringtun session with clean handshake
/// state. On a DNS blip we keep the last-known endpoint rather than tearing the
/// tunnel down — fail-open, since a transient resolver failure shouldn't kill an
/// otherwise-recoverable tunnel.
async fn rebuild_tunnel(cfg: &WgConfig) -> io::Result<Tunnel> {
    let endpoint = match resolve_endpoint(&cfg.endpoint_host).await {
        Ok(ep) => ep,
        Err(e) => {
            tracing::warn!(
                "wg re-resolve of {} failed ({e}); reusing last endpoint {}",
                cfg.endpoint_host, cfg.endpoint
            );
            cfg.endpoint
        }
    };
    Tunnel::new(
        cfg.private_key.clone(),
        cfg.peer_public_key,
        endpoint,
        cfg.persistent_keepalive,
    )
    .await
}

/// Build a [`WgConfig`] from the environment, or `None` if WireGuard is not
/// configured (no `WG_PRIVATE_KEY`). If WG *is* requested but a required value
/// is missing or invalid, this errors rather than silently falling back — a
/// misconfigured tunnel must fail loudly, not quietly route in the clear.
///
/// | Var | Required | Meaning |
/// |-----|----------|---------|
/// | `WG_PRIVATE_KEY` | gate | base64 32-byte private key (from a secret store) |
/// | `WG_PEER_PUBLIC_KEY` | yes | base64 public key of the peer box |
/// | `WG_ENDPOINT` | yes | peer UDP endpoint, e.g. `172.16.50.38:51820` |
/// | `WG_TARGET_ADDR` | yes | target over the tunnel, e.g. `10.99.0.2:8080` (`WG_INFERENCE_ADDR` accepted as a legacy alias) |
/// | `WG_ADDRESS` | no (`10.99.0.1`) | our IPv4 on the WG network |
/// | `WG_KEEPALIVE` | no (`25`) | persistent keepalive seconds |
/// | `WG_MTU` | no (`1420`) | tunnel MTU |
pub fn config_from_env() -> anyhow::Result<Option<WgConfig>> {
    let Some(private_b64) = std::env::var("WG_PRIVATE_KEY").ok().filter(|s| !s.is_empty()) else {
        return Ok(None); // WireGuard disabled
    };

    let private_key = StaticSecret::from(decode_key(&private_b64).context("WG_PRIVATE_KEY")?);
    let peer_public_key = PublicKey::from(
        decode_key(&std::env::var("WG_PEER_PUBLIC_KEY").context("WG_PEER_PUBLIC_KEY required")?)
            .context("WG_PEER_PUBLIC_KEY")?,
    );

    // Resolve WG_ENDPOINT as host:port so it accepts a DNS name (e.g. a DDNS
    // record that follows the box's DHCP IP), not only a literal address —
    // `SocketAddr::parse` is numeric-only. `to_socket_addrs` also resolves a bare
    // IP to itself, so existing IP configs keep working. It blocks briefly, which
    // is fine in this run-once-at-startup path (no async context here).
    let raw = std::env::var("WG_ENDPOINT").context("WG_ENDPOINT required")?;
    let endpoint: SocketAddr = raw
        .to_socket_addrs()
        .with_context(|| format!("WG_ENDPOINT: could not resolve {raw}"))?
        .next()
        .with_context(|| format!("WG_ENDPOINT resolved to no addresses: {raw}"))?;

    // WG_TARGET_ADDR is the name; WG_INFERENCE_ADDR is the legacy alias every
    // deployed consumer already carries — both keep working.
    let target: SocketAddr = std::env::var("WG_TARGET_ADDR")
        .or_else(|_| std::env::var("WG_INFERENCE_ADDR"))
        .context("WG_TARGET_ADDR (or WG_INFERENCE_ADDR) required")?
        .parse()
        .context("WG_TARGET_ADDR must be host:port")?;
    let IpAddr::V4(target_ip) = target.ip() else {
        anyhow::bail!("WG_TARGET_ADDR must be IPv4");
    };

    let address: Ipv4Addr = std::env::var("WG_ADDRESS")
        .unwrap_or_else(|_| "10.99.0.1".to_string())
        .parse()
        .context("WG_ADDRESS must be an IPv4 address")?;

    let persistent_keepalive = std::env::var("WG_KEEPALIVE")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(Some(25));
    let mtu = std::env::var("WG_MTU")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1420);

    Ok(Some(WgConfig {
        private_key,
        peer_public_key,
        endpoint,
        endpoint_host: raw,
        address,
        target_ip,
        target_port: target.port(),
        persistent_keepalive,
        mtu,
    }))
}

/// Decode a base64 (standard, padded) WireGuard key into 32 raw bytes.
fn decode_key(s: &str) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .context("invalid base64")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must decode to exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_health_thresholds() {
        let h = WgHealth::new();
        // No handshake yet → unknown, and not reported as "ok".
        assert_eq!(h.last_handshake_secs(), None);
        assert!(!h.handshake_ok());

        // A fresh handshake → session live.
        h.set(Some(Duration::from_secs(10)));
        assert_eq!(h.last_handshake_secs(), Some(10));
        assert!(h.handshake_ok());

        // At/over the session-lifetime boundary → dead (nothing renewed it).
        h.set(Some(Duration::from_secs(HANDSHAKE_STALE_SECS)));
        assert_eq!(h.last_handshake_secs(), Some(HANDSHAKE_STALE_SECS));
        assert!(!h.handshake_ok());

        // Clearing back to "never" reports unknown, not a misleading stale-zero.
        h.set(None);
        assert_eq!(h.last_handshake_secs(), None);
        assert!(!h.handshake_ok());
    }
}
