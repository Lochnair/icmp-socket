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
//! An ICMP socket library that tries to be ergonomic to use.
//!
//! The standard ping examples for both Ipv6 and IPv4 are in the examples
//! directory.
//!
//! The `async-io` feature provides an async-io backend, while `smol` remains a
//! backwards-compatible alias for it. The `tokio` feature provides a
//! first-class Tokio backend for ICMPv4 sockets on Unix.
pub mod packet;
pub mod socket;

pub use packet::{Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet};
pub use socket::{DgramIcmpSocket4, IcmpSocket, IcmpSocket4, IcmpSocket6};

#[cfg(any(feature = "async-io", feature = "tokio"))]
pub mod async_api;
#[cfg(any(feature = "async-io", all(feature = "tokio", unix)))]
mod async_common;
#[cfg(any(feature = "async-io", feature = "tokio"))]
pub use async_api::AsyncIcmpSocket;

#[cfg(feature = "async-io")]
pub mod async_io;

#[cfg(feature = "smol")]
pub mod smol {
    //! Backwards-compatible names for the [`crate::async_io`] backend.
    pub use crate::async_io::*;
}

#[cfg(all(feature = "tokio", unix))]
pub mod tokio;
