//! A `smoltcp` packet-queue device.
//!
//! `smoltcp` drives a virtual TCP/IP stack but needs a "device" to move raw IP
//! packets in and out. Here the device is just two in-memory queues: outbound
//! packets smoltcp produces land in `send` (the event loop drains them into the
//! WireGuard tunnel to be encrypted), and decrypted inbound packets are pushed
//! into `recv` for smoltcp to process. No real NIC, no syscalls.
//!
//! Adapted from `tokio-wireguard`'s `interface/device.rs`
//! (github.com/raftario/river, MIT OR Apache-2.0) and ported to smoltcp 0.13.
//! The `phy::Device`/`RxToken`/`TxToken` trait shapes are unchanged between
//! 0.11 and 0.13 (verified against the 0.13.1 docs), so this is near-verbatim;
//! the queue design (a flat byte ring + a length queue) is theirs.

use std::collections::VecDeque;

use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};

/// The virtual link between smoltcp and the WireGuard tunnel: a receive queue
/// (decrypted inbound IP packets) and a send queue (outbound IP packets smoltcp
/// wants transmitted).
pub struct Device {
    recv: Token,
    send: Token,
    mtu: usize,
}

impl Device {
    pub fn new(mtu: usize) -> Self {
        Self {
            recv: Token::new(),
            send: Token::new(),
            mtu,
        }
    }

    /// Push a decrypted inbound IP packet for smoltcp to process on its next poll.
    pub fn enqueue_received(&mut self, packet: &[u8]) {
        self.recv.queue.enqueue(packet);
    }

    /// Take the next outbound IP packet smoltcp has queued, if any. The returned
    /// slice borrows an internal buffer, so it is valid only until the next call.
    pub fn dequeue_sent(&mut self) -> Option<&[u8]> {
        if self.send.queue.is_empty() {
            return None;
        }
        self.send.queue.dequeue(&mut self.send.buffer);
        Some(&self.send.buffer)
    }
}

impl smoltcp::phy::Device for Device {
    type RxToken<'a> = &'a mut Token;
    type TxToken<'a> = &'a mut Token;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let Self { recv, send, .. } = self;
        if recv.queue.is_empty() {
            None
        } else {
            Some((recv, send))
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(&mut self.send)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = None;
        caps
    }
}

/// One direction's storage: a packet queue plus a scratch buffer reused when
/// handing a packet to (or receiving one from) a token consumer.
pub struct Token {
    queue: PacketQueue,
    buffer: Vec<u8>,
}

impl Token {
    const fn new() -> Self {
        Self {
            queue: PacketQueue::new(),
            buffer: Vec::new(),
        }
    }
}

impl RxToken for &mut Token {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.queue.dequeue(&mut self.buffer);
        f(&self.buffer)
    }
}

impl TxToken for &mut Token {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.buffer.resize(len, 0);
        let result = f(&mut self.buffer);
        self.queue.enqueue(&self.buffer);
        result
    }
}

/// A FIFO of variable-length packets stored as a flat byte ring plus a queue of
/// per-packet lengths — avoids a `Vec<Vec<u8>>` allocation per packet.
struct PacketQueue {
    lengths: VecDeque<usize>,
    buffers: VecDeque<u8>,
}

impl PacketQueue {
    const fn new() -> Self {
        Self {
            lengths: VecDeque::new(),
            buffers: VecDeque::new(),
        }
    }

    fn enqueue(&mut self, packet: &[u8]) {
        self.lengths.push_back(packet.len());
        self.buffers.extend(packet);
    }

    /// Pop the front packet into `buf`. If the queue is empty, `buf` is cleared
    /// and left empty (callers only dequeue after an `is_empty` check, but this
    /// stays panic-free regardless).
    fn dequeue(&mut self, buf: &mut Vec<u8>) {
        let len = self.lengths.pop_front().unwrap_or(0);
        buf.clear();
        buf.extend(self.buffers.drain(..len));
    }

    fn is_empty(&self) -> bool {
        self.lengths.is_empty()
    }
}
