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
//! ICMP Socket implementations for both ICMP4 and ICMP6 protocols.
//!
//! There is a common IcmpSocket trait implemented for both the v4 and v6 protocols.
//! The socket is associated to both an address type and packet type.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{
    convert::{Into, TryFrom, TryInto},
    mem::MaybeUninit,
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::packet::{Icmpv4Packet, Icmpv6Packet, WithEchoRequest};

pub fn ip_to_socket(ip: &IpAddr) -> SocketAddr {
    SocketAddr::new(*ip, 0)
}

/// Trait for an IcmpSocket implemented by Icmpv4Socket and Icmpv6Socket.
pub trait IcmpSocket {
    /// The type of address this socket operates on.
    type AddrType;
    /// The type of packet this socket handles.
    type PacketType;

    /// Sets the timeout on the socket for rcv_from. A value of None
    /// will cause rcv_from to block.
    fn set_timeout(&mut self, timeout: Option<Duration>);

    /// Sets the ttl for packets sent on this socket. Controls the number of
    /// hops the packet will be allowed to traverse.
    fn set_max_hops(&mut self, hops: u32);

    /// Binds this socket to an address.
    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()>;

    /// Sends the packet to the given destination.
    fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> std::io::Result<()>;

    /// Receive a packet on this socket.
    fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)>;
}

/// Options for this socket.
pub struct Opts {
    pub hops: u32,
    pub timeout: Option<Duration>,
}

/// Shared low-level state and operations for the ICMPv4 sockets. This keeps the
/// public socket types thin: the raw and datagram sockets differ only in how a
/// packet is sent, not in binding, receiving, or option handling.
struct Icmp4Core {
    inner: Socket,
    bound_to: Option<Ipv4Addr>,
    buf: Vec<u8>,
    opts: Opts,
}

impl Icmp4Core {
    fn from_socket(inner: Socket) -> std::io::Result<Self> {
        inner.set_recv_buffer_size(512)?;
        Ok(Self {
            inner,
            bound_to: None,
            buf: vec![0; 512],
            opts: Opts {
                hops: 50,
                timeout: None,
            },
        })
    }

    fn bind(&mut self, addr: Ipv4Addr) -> std::io::Result<()> {
        self.bound_to = Some(addr);
        let sock = ip_to_socket(&IpAddr::V4(addr));
        self.inner.bind(&(sock.into()))
    }

    /// The bound local port. On a datagram (ping) socket this is the ICMP
    /// identifier the kernel associates with the socket.
    fn local_identifier(&self) -> std::io::Result<u16> {
        let addr = self.inner.local_addr()?;
        Ok(addr.as_socket_ipv4().map(|s| s.port()).unwrap_or(0))
    }

    fn send_bytes(&self, dest: Ipv4Addr, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.set_ttl(self.opts.hops)?;
        let dest = ip_to_socket(&IpAddr::V4(dest));
        self.inner.send_to(bytes, &(dest.into()))?;
        Ok(())
    }

    fn recv(&mut self) -> std::io::Result<(Icmpv4Packet, SockAddr)> {
        self.inner.set_read_timeout(self.opts.timeout)?;
        // NOTE(jwall): the `recv_from` implementation promises not to write uninitialised
        // bytes to the `buf`fer, so this casting is safe.
        // TODO(jwall): change to `Vec::spare_capacity_mut` when it stabilizes.
        let mut buf =
            unsafe { &mut *(self.buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let (read_count, addr) = self.inner.recv_from(&mut buf)?;
        // Whether an IPv4 header is present depends on the OS and socket type,
        // so detect it from the bytes rather than assuming.
        let packet = Icmpv4Packet::parse_auto(&self.buf[0..read_count])?;
        Ok((packet, addr))
    }
}

/// A raw (SOCK_RAW) ICMPv4 socket. Requires elevated privileges. The caller
/// constructs and owns the full packet, including its identifier.
pub struct IcmpSocket4 {
    core: Icmp4Core,
}

impl IcmpSocket4 {
    /// Construct a new raw socket. The socket must be bound to an address using `bind`
    /// before it can be used to send and receive packets.
    pub fn new() -> std::io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        Ok(Self {
            core: Icmp4Core::from_socket(socket)?,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.bound_to
    }

    #[cfg(feature = "smol")]
    pub fn into_async(self) -> std::io::Result<crate::smol::AsyncIcmpV4Socket> {
        let Icmp4Core {
            inner,
            bound_to,
            buf,
            opts,
        } = self.core;
        crate::smol::AsyncIcmpV4Socket::new(inner, bound_to, buf, opts)
    }
}

impl IcmpSocket for IcmpSocket4 {
    type AddrType = Ipv4Addr;
    type PacketType = Icmpv4Packet;

    fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = hops;
    }

    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> std::io::Result<()> {
        self.core
            .send_bytes(dest, &packet.with_checksum().get_bytes(true))
    }

    fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        self.core.recv()
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }
}

/// A datagram (SOCK_DGRAM) ICMPv4 "ping" socket. Usable without elevated
/// privileges where the OS permits it (macOS, and Linux when
/// `net.ipv4.ping_group_range` includes the running user's gid).
///
/// Unlike the raw socket, the identifier is not the caller's to choose: on
/// Linux the kernel overwrites the packet's identifier with the socket's local
/// port. This type therefore owns the identifier — derived from the bound port
/// and reported by [`Self::identifier`] — and its [`Self::send`] takes only the
/// sequence and payload. Match replies against [`Self::identifier`].
pub struct DgramIcmpSocket4 {
    core: Icmp4Core,
    identifier: u16,
}

impl DgramIcmpSocket4 {
    /// Construct a new datagram socket. It must be bound with [`Self::bind`]
    /// before sending so that its identifier is established.
    pub fn new() -> std::io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        Ok(Self {
            core: Icmp4Core::from_socket(socket)?,
            identifier: 0,
        })
    }

    /// Bind the socket and establish its identifier from the assigned local
    /// port.
    pub fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())?;
        self.identifier = self.core.local_identifier()?;
        Ok(())
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.bound_to
    }

    /// The ICMP identifier this socket uses on the wire. Use it to match replies
    /// that belong to this socket. Meaningful only after [`Self::bind`].
    ///
    /// This is the bound local port. On Linux that is a unique kernel-assigned
    /// value; on macOS a datagram ICMP socket is not assigned a port, so this
    /// is `0` and is not unique across sockets.
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Sets the ttl for packets sent on this socket.
    pub fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = hops;
    }

    /// Sets the timeout on the socket for `rcv_from`. A value of None blocks.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }

    /// Send an echo request to `dest`. The identifier is supplied by the socket,
    /// so the caller provides only the sequence number and payload.
    pub fn send(&mut self, dest: Ipv4Addr, sequence: u16, payload: Vec<u8>) -> std::io::Result<()> {
        let packet = Icmpv4Packet::with_echo_request(self.identifier, sequence, payload)?;
        self.core
            .send_bytes(dest, &packet.with_checksum().get_bytes(true))
    }

    /// Receive a packet. Replies are not filtered; compare against
    /// [`Self::identifier`] to select those belonging to this socket.
    pub fn rcv_from(&mut self) -> std::io::Result<(Icmpv4Packet, SockAddr)> {
        self.core.recv()
    }

    #[cfg(feature = "smol")]
    pub fn into_async(self) -> std::io::Result<crate::smol::AsyncDgramIcmpV4Socket> {
        let Icmp4Core {
            inner,
            bound_to,
            buf,
            opts,
        } = self.core;
        crate::smol::AsyncDgramIcmpV4Socket::new(inner, bound_to, buf, opts, self.identifier)
    }
}

/// An Icmpv6 socket.
pub struct IcmpSocket6 {
    bound_to: Option<Ipv6Addr>,
    inner: Socket,
    buf: Vec<u8>,
    opts: Opts,
}

impl IcmpSocket6 {
    /// Construct a new raw socket. The socket must be bound to an address using `bind_to`
    /// before it can be used to send and receive packets.
    pub fn new() -> std::io::Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        Self::new_from_socket(socket)
    }

    fn new_from_socket(socket: Socket) -> std::io::Result<Self> {
        socket.set_recv_buffer_size(512)?;
        Ok(Self {
            bound_to: None,
            inner: socket,
            buf: vec![0; 512],
            opts: Opts {
                hops: 50,
                timeout: None,
            },
        })
    }
}

impl IcmpSocket for IcmpSocket6 {
    type AddrType = Ipv6Addr;
    type PacketType = Icmpv6Packet;

    fn set_max_hops(&mut self, hops: u32) {
        self.opts.hops = hops;
    }

    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()> {
        let addr = addr.into();
        self.bound_to = Some(addr.clone());
        let sock = ip_to_socket(&IpAddr::V6(addr));
        self.inner.bind(&(sock.into()))?;
        Ok(())
    }

    fn send_to(
        &mut self,
        dest: Self::AddrType,
        mut packet: Self::PacketType,
    ) -> std::io::Result<()> {
        let source = match self.bound_to {
            Some(ref addr) => addr,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Socket not bound to an address",
                ))
            }
        };
        packet = packet.with_checksum(source, &dest);
        let dest = ip_to_socket(&IpAddr::V6(dest));
        self.inner.set_unicast_hops_v6(self.opts.hops)?;
        let pkt = packet.get_bytes(true);
        self.inner.send_to(&pkt, &(dest.into()))?;
        Ok(())
    }

    fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        self.inner.set_read_timeout(self.opts.timeout)?;
        // NOTE(jwall): the `recv_from` implementation promises not to write uninitialised
        // bytes to the `buf`fer, so this casting is safe.
        // TODO(jwall): change to `Vec::spare_capacity_mut` when it stabilizes.
        let mut buf =
            unsafe { &mut *(self.buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let (read_count, addr) = self.inner.recv_from(&mut buf)?;
        Ok((self.buf[0..read_count].try_into()?, addr))
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.opts.timeout = timeout;
    }
}

impl TryFrom<Ipv4Addr> for IcmpSocket4 {
    type Error = std::io::Error;

    fn try_from(addr: Ipv4Addr) -> Result<Self, Self::Error> {
        let mut sock = IcmpSocket4::new()?;
        sock.bind(addr)?;
        Ok(sock)
    }
}

impl TryFrom<Ipv6Addr> for IcmpSocket6 {
    type Error = std::io::Error;

    fn try_from(addr: Ipv6Addr) -> Result<Self, Self::Error> {
        let mut sock = IcmpSocket6::new()?;
        sock.bind(addr)?;
        Ok(sock)
    }
}
