// Copyright 2021 Jeremy Wall
// Copyright 2026 Nils Andreas Svee
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Tokio ICMP socket implementations for Unix.
//!
//! This crate does not create or own a Tokio runtime. Call `into_tokio()` from
//! within an entered runtime context so Tokio can register the socket with its
//! reactor.

use std::{
    future::poll_fn,
    io,
    net::Ipv4Addr,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use socket2::{SockAddr, Socket};
use tokio::io::{Interest, unix::AsyncFd};

const IO_POLL_WORK_BUDGET: usize = 64;

pub use crate::async_api::AsyncIcmpSocket;
use crate::{
    async_common::{AsyncIcmp4State, dgram_packet_bytes, raw_packet_bytes, timeout_error},
    packet::Icmpv4Packet,
    socket::Opts,
};

struct AsyncIcmp4Core {
    inner: AsyncFd<Socket>,
    state: AsyncIcmp4State,
}

impl AsyncIcmp4Core {
    fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
    ) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(|error| {
            io::Error::other(format!(
                "into_tokio requires an entered Tokio runtime: {error}"
            ))
        })?;
        inner.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(inner)?,
            state: AsyncIcmp4State::new(bound_to, buf, opts),
        })
    }

    fn bind(&mut self, addr: Ipv4Addr) -> io::Result<()> {
        self.state.bind(self.inner.get_ref(), addr)
    }

    fn local_identifier(&self) -> io::Result<u16> {
        AsyncIcmp4State::local_identifier(self.inner.get_ref())
    }

    fn enable_receive_metadata(&self) -> io::Result<()> {
        crate::receive::configure(self.inner.get_ref())
    }

    fn poll_send_bytes(
        &self,
        cx: &mut Context<'_>,
        dest: Ipv4Addr,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let dest = match self.state.prepare_send(self.inner.get_ref(), dest) {
            Ok(dest) => dest,
            Err(error) => return Poll::Ready(Err(error)),
        };
        for _ in 0..IO_POLL_WORK_BUDGET {
            let mut ready = match self.inner.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ready)) => ready,
            };
            match ready.try_io(|inner| inner.get_ref().send_to(bytes, &dest)) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    async fn send_bytes(&self, dest: Ipv4Addr, bytes: &[u8]) -> io::Result<()> {
        poll_fn(|cx| self.poll_send_bytes(cx, dest, bytes))
            .await
            .map(|_| ())
    }

    fn poll_recv_with_meta(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<crate::IcmpReceiveResult<Icmpv4Packet>>> {
        for _ in 0..IO_POLL_WORK_BUDGET {
            let mut ready = match self.inner.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ready)) => ready,
            };
            match ready.try_io(|inner| self.state.receive_with_meta(inner.get_ref())) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    async fn recv(&mut self) -> io::Result<(Icmpv4Packet, SockAddr)> {
        let timeout = self.state.timeout();
        let recv = self.inner.async_io(Interest::READABLE, |socket| {
            socket.recv_from(self.state.begin_receive())
        });
        let (read_count, peer) = match timeout {
            Some(duration) => tokio::time::timeout(duration, recv)
                .await
                .map_err(|_| timeout_error())??,
            None => recv.await?,
        };
        Ok((self.state.finish_receive(read_count)?, peer))
    }

    async fn recv_with_meta(&mut self) -> io::Result<crate::IcmpReceiveResult<Icmpv4Packet>> {
        let timeout = self.state.timeout();
        let recv = poll_fn(|cx| self.poll_recv_with_meta(cx));
        match timeout {
            Some(duration) => tokio::time::timeout(duration, recv)
                .await
                .map_err(|_| timeout_error())?,
            None => recv.await,
        }
    }
}

/// An async raw (SOCK_RAW) ICMPv4 socket driven by Tokio on Unix.
pub struct AsyncIcmpV4Socket {
    core: AsyncIcmp4Core,
}

impl AsyncIcmpV4Socket {
    /// Replace the Linux kernel receive filter with an ICMPv4 type allow-list.
    ///
    /// See [`crate::IcmpSocket4::set_allowed_types`] for type numbers, the
    /// IPv4 filter's 0 through 31 limit, and shared-socket semantics.
    #[cfg(target_os = "linux")]
    pub fn set_allowed_types(&self, allowed: &[u8]) -> io::Result<()> {
        crate::filter::set_allowed_types_v4(self.core.inner.get_ref(), allowed)
    }

    /// Restore the Linux kernel receive filter to allow all ICMPv4 types.
    #[cfg(target_os = "linux")]
    pub fn clear_type_filter(&self) -> io::Result<()> {
        crate::filter::clear_type_filter_v4(self.core.inner.get_ref())
    }

    /// Register a socket with the current Tokio runtime. Construct one via
    /// [`crate::IcmpSocket4::into_tokio`].
    pub(crate) fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
    ) -> io::Result<Self> {
        Ok(Self {
            core: AsyncIcmp4Core::new(inner, bound_to, buf, opts)?,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.state.bound_to()
    }

    /// Set the size of the per-read receive buffer (default 2048 bytes).
    pub fn set_read_buffer_size(&mut self, size: usize) {
        self.core.state.set_read_buffer_size(size);
    }

    /// Poll one raw ICMPv4 send, computing the packet checksum as `send_to` does.
    ///
    /// Pending registers the write waker and transmits nothing. Retain the
    /// packet/destination until retry, or simply stop polling to abandon it.
    /// Ok(bytes) means socket acceptance: account for the send before doing any
    /// fallible post-processing. This method owns no sequence or retry state.
    /// Use one owner per readiness direction; reads may progress between polls.
    pub fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        dest: Ipv4Addr,
        packet: &Icmpv4Packet,
    ) -> Poll<io::Result<usize>> {
        let mut bytes = packet.get_bytes(false);
        bytes[2..4].copy_from_slice(&packet.calculate_checksum().to_be_bytes());
        self.core.poll_send_bytes(cx, dest, &bytes)
    }

    /// Poll bounded receive work with metadata, registering the read waker.
    /// No socket timeout is applied: the caller owns its timer. Pending has
    /// consumed no packet; read and write polling may be interleaved by one owner.
    pub fn poll_recv_from_with_meta(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<crate::IcmpReceiveResult<Icmpv4Packet>>> {
        self.core.poll_recv_with_meta(cx)
    }

    /// Receive a packet together with the metadata available on the socket.
    ///
    /// On Linux, call [`Self::enable_receive_metadata`] before traffic can
    /// arrive to request kernel RX timestamps. Without doing so,
    /// `kernel_rx_timestamp` may be `None`.
    pub async fn rcv_from_with_meta(
        &mut self,
    ) -> io::Result<crate::IcmpReceiveResult<Icmpv4Packet>> {
        self.core.recv_with_meta().await
    }

    /// Enable receive metadata before traffic can arrive.
    pub fn enable_receive_metadata(&self) -> io::Result<()> {
        self.core.enable_receive_metadata()
    }
}

#[async_trait]
impl AsyncIcmpSocket for AsyncIcmpV4Socket {
    type AddrType = Ipv4Addr;
    type PacketType = Icmpv4Packet;

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.state.set_timeout(timeout);
    }

    fn set_max_hops(&mut self, hops: u32) {
        self.core.state.set_max_hops(hops);
    }

    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> io::Result<()> {
        self.core.bind(addr.into())
    }

    async fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> io::Result<()> {
        self.core.send_bytes(dest, &raw_packet_bytes(packet)).await
    }

    async fn rcv_from(&mut self) -> io::Result<(Self::PacketType, SockAddr)> {
        self.core.recv().await
    }
}

/// An async datagram (SOCK_DGRAM) ICMPv4 "ping" socket driven by Tokio on Unix.
pub struct AsyncDgramIcmpV4Socket {
    core: AsyncIcmp4Core,
    identifier: u16,
}

impl AsyncDgramIcmpV4Socket {
    /// Register a socket with the current Tokio runtime. Construct one via
    /// [`crate::DgramIcmpSocket4::into_tokio`].
    pub(crate) fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
        identifier: u16,
    ) -> io::Result<Self> {
        Ok(Self {
            core: AsyncIcmp4Core::new(inner, bound_to, buf, opts)?,
            identifier,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.state.bound_to()
    }

    /// Set the size of the per-read receive buffer (default 2048 bytes).
    pub fn set_read_buffer_size(&mut self, size: usize) {
        self.core.state.set_read_buffer_size(size);
    }

    /// The ICMP identifier this socket uses on the wire.
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Sets the timeout on the socket for `rcv_from`.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.state.set_timeout(timeout);
    }

    /// Sets the TTL for packets sent on this socket.
    pub fn set_max_hops(&mut self, hops: u32) {
        self.core.state.set_max_hops(hops);
    }

    /// Bind the socket and establish its identifier from the assigned local
    /// port.
    pub async fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> io::Result<()> {
        self.core.bind(addr.into())?;
        self.identifier = self.core.local_identifier()?;
        Ok(())
    }

    /// Poll an echo send without waiting. Pending registers the write waker
    /// and accepts no datagram; Ok(bytes) is the accepted transmission.
    /// Keep inputs unchanged across retries or stop polling to abandon them.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        dest: Ipv4Addr,
        sequence: u16,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        let bytes = match dgram_packet_bytes(self.identifier, sequence, payload.to_vec()) {
            Ok(bytes) => bytes,
            Err(error) => return Poll::Ready(Err(error)),
        };
        self.core.poll_send_bytes(cx, dest, &bytes)
    }

    /// Poll bounded receive work with metadata. Caller-owned deadlines replace
    /// the receive timeout for this operation. Use one read readiness owner.
    pub fn poll_recv_from_with_meta(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<crate::IcmpReceiveResult<Icmpv4Packet>>> {
        self.core.poll_recv_with_meta(cx)
    }

    /// Send an echo request to `dest`.
    pub async fn send(
        &mut self,
        dest: Ipv4Addr,
        sequence: u16,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let bytes = dgram_packet_bytes(self.identifier, sequence, payload)?;
        self.core.send_bytes(dest, &bytes).await
    }

    /// Receive a packet without filtering replies.
    pub async fn rcv_from(&mut self) -> io::Result<(Icmpv4Packet, SockAddr)> {
        self.core.recv().await
    }

    /// Receive a packet together with the metadata available on the socket.
    ///
    /// On Linux, call [`Self::enable_receive_metadata`] before traffic can
    /// arrive to request kernel RX timestamps. Without doing so,
    /// `kernel_rx_timestamp` may be `None`.
    pub async fn rcv_from_with_meta(
        &mut self,
    ) -> io::Result<crate::IcmpReceiveResult<Icmpv4Packet>> {
        self.core.recv_with_meta().await
    }

    /// Enable receive metadata before traffic can arrive.
    pub fn enable_receive_metadata(&self) -> io::Result<()> {
        self.core.enable_receive_metadata()
    }
}
