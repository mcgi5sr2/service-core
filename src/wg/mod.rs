//! In-process userspace WireGuard transport.
//!
//! The consumer runs the entire WireGuard tunnel inside its own process — no TUN
//! device, no `NET_ADMIN` capability — and exposes one service reachable over the
//! tunnel on a loopback port. The application then talks plain HTTP to
//! `127.0.0.1:<port>`; all the tunnel complexity is hidden behind that local
//! socket.
//!
//! Built on `boringtun` (the WireGuard noise protocol) + `smoltcp` (a userspace
//! TCP/IP stack). The structure mirrors the reference implementation
//! `tokio-wireguard` (github.com/raftario/river, MIT OR Apache-2.0), trimmed to
//! a single-target forwarder rather than a general-purpose interface.
//!
//! This module is the ONE copy of a stack that previously lived per-service —
//! the same defect was once found and fixed twice in two identical copies, which
//! is exactly the drift a shared crate exists to stop. It carries its own
//! self-heal: a handshake watchdog that re-resolves the peer endpoint (DDNS-
//! tolerant) and rebuilds the tunnel on stall, and a cheap [`forward::WgHealth`]
//! handle so every consumer's `/health` can report `handshake_ok` honestly.
//!
//! Modules (in dependency order):
//! - [`device`] — the smoltcp packet-queue device (no boringtun)
//! - [`tunnel`] — the boringtun `Tunn` wrapper (encrypt/decrypt/timers)
//! - [`forward`] — the event loop, watchdog and loopback shuttle

pub mod device;
pub mod forward;
pub mod tunnel;
