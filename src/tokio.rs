// Copyright 2021 Jeremy Wall
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

use std::{io, net::Ipv4Addr, time::Duration};

use async_trait::async_trait;
use socket2::{SockAddr, Socket};
use tokio::io::{Interest, unix::AsyncFd};

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

    async fn send_bytes(&self, dest: Ipv4Addr, bytes: &[u8]) -> io::Result<()> {
        let dest = self.state.prepare_send(self.inner.get_ref(), dest)?;
        self.inner
            .async_io(Interest::WRITABLE, |socket| socket.send_to(bytes, &dest))
            .await?;
        Ok(())
    }

    async fn recv(&mut self) -> io::Result<(Icmpv4Packet, SockAddr)> {
        let timeout = self.state.timeout();
        let recv = self.inner.async_io(Interest::READABLE, |socket| {
            socket.recv_from(self.state.begin_receive())
        });
        let (read_count, addr) = match timeout {
            Some(duration) => tokio::time::timeout(duration, recv)
                .await
                .map_err(|_| timeout_error())??,
            None => recv.await?,
        };
        let packet = self.state.finish_receive(read_count)?;
        Ok((packet, addr))
    }
}

/// An async raw (SOCK_RAW) ICMPv4 socket driven by Tokio on Unix.
pub struct AsyncIcmpV4Socket {
    core: AsyncIcmp4Core,
}

impl AsyncIcmpV4Socket {
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
}
