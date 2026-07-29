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
//! Async ICMP socket implementations driven by the `async-io` reactor.
//!
//! This is the backend historically exposed by this crate's `smol` feature.
//! The `smol` feature and module remain compatibility aliases, but this backend
//! depends directly on `async-io` and `futures-lite`, not the smol runtime
//! umbrella crate.

use std::{net::Ipv4Addr, time::Duration};

use ::async_io::{Async, Timer};
use async_trait::async_trait;
use futures_lite::future::FutureExt;
use socket2::{SockAddr, Socket};

pub use crate::async_api::AsyncIcmpSocket;
use crate::{
    async_common::{AsyncIcmp4State, dgram_packet_bytes, raw_packet_bytes, timeout_error},
    packet::Icmpv4Packet,
    socket::Opts,
};

struct AsyncIcmp4Core {
    inner: Async<Socket>,
    state: AsyncIcmp4State,
}

impl AsyncIcmp4Core {
    fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: Async::new(inner)?,
            state: AsyncIcmp4State::new(bound_to, buf, opts),
        })
    }

    fn bind(&mut self, addr: Ipv4Addr) -> std::io::Result<()> {
        self.state.bind(self.inner.get_ref(), addr)
    }

    fn local_identifier(&self) -> std::io::Result<u16> {
        AsyncIcmp4State::local_identifier(self.inner.get_ref())
    }

    async fn send_bytes(&self, dest: Ipv4Addr, bytes: &[u8]) -> std::io::Result<()> {
        let dest = self.state.prepare_send(self.inner.get_ref(), dest)?;
        self.inner
            .write_with(|socket| socket.send_to(bytes, &dest))
            .await?;
        Ok(())
    }

    async fn recv(&mut self) -> std::io::Result<(Icmpv4Packet, SockAddr)> {
        let timeout = self.state.timeout();
        let inner = &self.inner;
        let recv = inner.read_with(|socket| socket.recv_from(self.state.begin_receive()));
        let (read_count, addr) = match timeout {
            Some(duration) => {
                recv.or(async move {
                    Timer::after(duration).await;
                    Err(timeout_error())
                })
                .await?
            }
            None => recv.await?,
        };
        let packet = self.state.finish_receive(read_count)?;
        Ok((packet, addr))
    }
}

/// An async raw (SOCK_RAW) ICMPv4 socket driven by `async-io`.
pub struct AsyncIcmpV4Socket {
    core: AsyncIcmp4Core,
}

impl AsyncIcmpV4Socket {
    /// Wrap a blocking socket in `async-io`. Construct one via
    /// [`crate::IcmpSocket4::into_async_io`] or the compatibility
    /// [`crate::IcmpSocket4::into_async`].
    pub(crate) fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
    ) -> std::io::Result<Self> {
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

    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    async fn send_to(
        &mut self,
        dest: Self::AddrType,
        packet: Self::PacketType,
    ) -> std::io::Result<()> {
        self.core.send_bytes(dest, &raw_packet_bytes(packet)).await
    }

    async fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        self.core.recv().await
    }
}

/// An async datagram (SOCK_DGRAM) ICMPv4 "ping" socket driven by `async-io`.
pub struct AsyncDgramIcmpV4Socket {
    core: AsyncIcmp4Core,
    identifier: u16,
}

impl AsyncDgramIcmpV4Socket {
    /// Construct one via [`crate::DgramIcmpSocket4::into_async_io`] or the
    /// compatibility [`crate::DgramIcmpSocket4::into_async`].
    pub(crate) fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
        identifier: u16,
    ) -> std::io::Result<Self> {
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
    pub async fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> std::io::Result<()> {
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
    ) -> std::io::Result<()> {
        let bytes = dgram_packet_bytes(self.identifier, sequence, payload)?;
        self.core.send_bytes(dest, &bytes).await
    }

    /// Receive a packet without filtering replies.
    pub async fn rcv_from(&mut self) -> std::io::Result<(Icmpv4Packet, SockAddr)> {
        self.core.recv().await
    }
}
