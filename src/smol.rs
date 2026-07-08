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
//! Async ICMP socket implementations built on the [`smol`] runtime.
//!
//! This module is gated behind the `smol` feature. Obtain an async socket by
//! constructing a [`crate::IcmpSocket4`] and calling `into_async`.
use std::{
    convert::TryFrom,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use async_trait::async_trait;
use smol::{future::FutureExt, Async, Timer};
use socket2::{SockAddr, Socket};

use crate::{
    packet::Icmpv4Packet,
    socket::{ip_to_socket, Opts},
};

/// An async ICMPv4 socket driven by the smol reactor.
pub struct AsyncIcmpV4Socket {
    inner: Async<Socket>,
    bound_to: Option<Ipv4Addr>,
    buf: Vec<u8>,
    opts: Opts,
}

impl AsyncIcmpV4Socket {
    /// Wrap a blocking [`Socket`] in the smol reactor. Registering the socket
    /// with the reactor can fail, so this returns a `Result` rather than
    /// panicking.
    pub fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: Async::new(inner)?,
            bound_to,
            buf,
            opts,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.bound_to
    }
}

#[async_trait]
pub trait AsyncIcmpSocket {
    /// The type of address this socket operates on.
    type AddrType;
    /// The type of packet this socket handles.
    type PacketType;

    /// Sets the timeout on the socket for `rcv_from`. A value of None
    /// will cause `rcv_from` to wait indefinitely.
    fn set_timeout(&mut self, timeout: Option<Duration>);

    /// Sets the ttl for packets sent on this socket. Controls the number of
    /// hops the packet will be allowed to traverse.
    fn set_max_hops(&mut self, hops: u32);

    /// Binds this socket to an address.
    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> std::io::Result<()>;

    /// Sends the packet to the given destination.
    async fn send_to(
        &mut self,
        dest: Self::AddrType,
        packet: Self::PacketType,
    ) -> std::io::Result<()>;

    /// Receive a packet on this socket.
    async fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)>;
}

#[async_trait]
impl AsyncIcmpSocket for AsyncIcmpV4Socket {
    type AddrType = Ipv4Addr;
    type PacketType = Icmpv4Packet;

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.opts.timeout = timeout;
    }

    fn set_max_hops(&mut self, hops: u32) {
        self.opts.hops = hops;
    }

    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> std::io::Result<()> {
        let addr = addr.into();
        self.bound_to = Some(addr);
        let sock = ip_to_socket(&IpAddr::V4(addr));
        // Binding a raw socket does not block, so it is safe to call directly
        // on the underlying descriptor.
        self.inner.get_ref().bind(&(sock.into()))?;
        Ok(())
    }

    async fn send_to(
        &mut self,
        dest: Self::AddrType,
        packet: Self::PacketType,
    ) -> std::io::Result<()> {
        self.inner.get_ref().set_ttl(self.opts.hops)?;
        let bytes = packet.with_checksum().get_bytes(true);
        let dest: SockAddr = ip_to_socket(&IpAddr::V4(dest)).into();
        self.inner
            .write_with(|sock| sock.send_to(&bytes, &dest))
            .await?;
        Ok(())
    }

    async fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        let timeout = self.opts.timeout;
        let inner = &self.inner;
        let buf = &mut self.buf;
        // NOTE(jwall): the `recv_from` implementation promises not to write
        // uninitialised bytes to the buffer, so this cast is safe.
        let recv = async {
            let uninit =
                unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
            inner.read_with(|sock| sock.recv_from(uninit)).await
        };
        let (read_count, addr) = match timeout {
            Some(t) => {
                recv.or(async move {
                    Timer::after(t).await;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rcv_from timed out",
                    ))
                })
                .await?
            }
            None => recv.await?,
        };
        let pkt = Icmpv4Packet::try_from(&self.buf[0..read_count])?;
        Ok((pkt, addr))
    }
}
