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

use std::io;

use nix::{libc, setsockopt_impl, sockopt_impl, sys::socket::setsockopt};
use socket2::Socket;

// Linux UAPI: linux/icmp.h and linux/icmpv6.h. Both options use number 1,
// at SOL_RAW for IPv4 and IPPROTO_ICMPV6 for IPv6.
const ICMP_FILTER: libc::c_int = 1;
const ICMP6_FILTER: libc::c_int = 1;

// The Linux filter structures contain one native-endian u32 for IPv4 and
// eight for IPv6. Nix supplies the typed socket option and syscall wrapper.
sockopt_impl!(IcmpFilter4, SetOnly, libc::SOL_RAW, ICMP_FILTER, u32);
sockopt_impl!(
    IcmpFilter6,
    SetOnly,
    libc::IPPROTO_ICMPV6,
    ICMP6_FILTER,
    [u32; 8]
);

pub(crate) fn set_allowed_types_v4(socket: &Socket, allowed: &[u8]) -> io::Result<()> {
    let mut mask = u32::MAX;
    for &typ in allowed {
        let bit = 1u32.checked_shl(u32::from(typ)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux ICMP_FILTER only supports ICMPv4 types 0 through 31",
            )
        })?;
        mask &= !bit;
    }
    setsockopt(socket, IcmpFilter4, &mask).map_err(Into::into)
}

pub(crate) fn clear_type_filter_v4(socket: &Socket) -> io::Result<()> {
    setsockopt(socket, IcmpFilter4, &0).map_err(Into::into)
}

pub(crate) fn set_allowed_types_v6(socket: &Socket, allowed: &[u8]) -> io::Result<()> {
    let mut mask = [u32::MAX; 8];
    for &typ in allowed {
        mask[usize::from(typ / 32)] &= !(1u32 << (typ % 32));
    }
    setsockopt(socket, IcmpFilter6, &mask).map_err(Into::into)
}

pub(crate) fn clear_type_filter_v6(socket: &Socket) -> io::Result<()> {
    setsockopt(socket, IcmpFilter6, &[0; 8]).map_err(Into::into)
}
