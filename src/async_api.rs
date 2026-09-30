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
//! Backend-neutral asynchronous ICMP socket API.

use std::time::Duration;

use async_trait::async_trait;
use socket2::SockAddr;

/// Common asynchronous operations implemented by each raw ICMP backend.
///
/// The `async-trait` transformation keeps the returned futures `Send` as part
/// of the public contract.
#[async_trait]
pub trait AsyncIcmpSocket {
    /// The type of address this socket operates on.
    type AddrType;
    /// The type of packet this socket handles.
    type PacketType;

    /// Sets the timeout on the socket for `rcv_from`. A value of `None`
    /// causes `rcv_from` to wait indefinitely.
    fn set_timeout(&mut self, timeout: Option<Duration>);

    /// Sets the TTL for packets sent on this socket.
    fn set_max_hops(&mut self, hops: u32);

    /// Binds this socket to an address.
    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> std::io::Result<()>;

    /// Sends the packet to the given destination.
    async fn send_to(
        &mut self,
        dest: Self::AddrType,
        packet: Self::PacketType,
    ) -> std::io::Result<()>;

    /// Receives a packet on this socket.
    async fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)>;
}
