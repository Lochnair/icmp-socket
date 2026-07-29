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

use std::{
    io,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use socket2::{SockAddr, Socket};

use crate::{
    packet::{Icmpv4Packet, WithEchoRequest},
    socket::{Opts, ip_to_socket, truncated_error},
};

pub(crate) struct AsyncIcmp4State {
    bound_to: Option<Ipv4Addr>,
    buf: Vec<u8>,
    opts: Opts,
}

impl AsyncIcmp4State {
    pub(crate) fn new(bound_to: Option<Ipv4Addr>, buf: Vec<u8>, opts: Opts) -> Self {
        Self {
            bound_to,
            buf,
            opts,
        }
    }

    pub(crate) fn bound_to(&self) -> Option<Ipv4Addr> {
        self.bound_to
    }

    pub(crate) fn set_read_buffer_size(&mut self, size: usize) {
        self.buf.resize(size, 0);
        self.buf.shrink_to_fit();
    }

    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.opts.timeout = timeout;
    }

    pub(crate) fn timeout(&self) -> Option<Duration> {
        self.opts.timeout
    }

    pub(crate) fn set_max_hops(&mut self, hops: u32) {
        self.opts.hops = hops;
    }

    pub(crate) fn bind(&mut self, socket: &Socket, addr: Ipv4Addr) -> io::Result<()> {
        self.bound_to = Some(addr);
        let sock = ip_to_socket(&IpAddr::V4(addr));
        socket.bind(&(sock.into()))
    }

    pub(crate) fn local_identifier(socket: &Socket) -> io::Result<u16> {
        let addr = socket.local_addr()?;
        Ok(addr.as_socket_ipv4().map(|s| s.port()).unwrap_or(0))
    }

    pub(crate) fn prepare_send(&self, socket: &Socket, dest: Ipv4Addr) -> io::Result<SockAddr> {
        socket.set_ttl_v4(self.opts.hops)?;
        Ok(ip_to_socket(&IpAddr::V4(dest)).into())
    }

    pub(crate) fn begin_receive(&mut self) -> &mut [MaybeUninit<u8>] {
        self.buf.clear();
        self.buf.spare_capacity_mut()
    }

    pub(crate) fn finish_receive(&mut self, read_count: usize) -> io::Result<Icmpv4Packet> {
        if read_count == self.buf.capacity() {
            return Err(truncated_error());
        }

        unsafe {
            self.buf.set_len(read_count);
        }

        Ok(Icmpv4Packet::parse_auto(&self.buf[0..read_count])?)
    }
}

pub(crate) fn raw_packet_bytes(packet: Icmpv4Packet) -> Vec<u8> {
    packet.with_checksum().get_bytes(true)
}

pub(crate) fn dgram_packet_bytes(
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let packet = Icmpv4Packet::with_echo_request(identifier, sequence, payload)?;
    Ok(raw_packet_bytes(packet))
}

pub(crate) fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "rcv_from timed out")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Icmpv4Message;

    fn state_with_buffer(size: usize) -> AsyncIcmp4State {
        AsyncIcmp4State::new(
            None,
            vec![0; size],
            Opts {
                hops: 50,
                timeout: None,
            },
        )
    }

    fn write_receive_bytes(state: &mut AsyncIcmp4State, bytes: &[u8]) {
        let spare = state.begin_receive();
        for (slot, byte) in spare.iter_mut().zip(bytes) {
            slot.write(*byte);
        }
    }

    #[test]
    fn full_receive_buffer_reports_truncation() {
        let mut state = state_with_buffer(8);
        write_receive_bytes(&mut state, &[0; 8]);

        let error = state.finish_receive(8).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("may be truncated"));
    }

    #[test]
    fn receive_finalization_parses_headerless_packet() {
        let bytes = dgram_packet_bytes(42, 7, vec![1, 2, 3, 4]).unwrap();
        let mut state = state_with_buffer(64);
        write_receive_bytes(&mut state, &bytes);

        let packet = state.finish_receive(bytes.len()).unwrap();
        assert!(packet.verify_checksum());
        assert!(matches!(
            packet.message,
            Icmpv4Message::Echo {
                identifier: 42,
                sequence: 7,
                ..
            }
        ));
    }

    #[test]
    fn receive_buffer_can_be_resized() {
        let mut state = state_with_buffer(8);
        state.set_read_buffer_size(32);
        assert_eq!(state.begin_receive().len(), 32);
    }

    #[test]
    fn timeout_error_preserves_public_contract() {
        let error = timeout_error();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "rcv_from timed out");
    }

    #[test]
    fn state_configuration_helpers_round_trip() {
        let mut state = state_with_buffer(8);
        let timeout = Duration::from_millis(250);
        state.set_timeout(Some(timeout));
        state.set_max_hops(17);

        assert_eq!(state.timeout(), Some(timeout));
        assert_eq!(state.opts.hops, 17);
        assert_eq!(state.bound_to(), None);
    }

    #[test]
    fn packet_preparation_sets_checksum_and_identifier() {
        let bytes = dgram_packet_bytes(123, 9, vec![5, 6]).unwrap();
        let packet = Icmpv4Packet::parse_dgram(bytes).unwrap();

        assert!(packet.verify_checksum());
        assert!(matches!(
            packet.message,
            Icmpv4Message::Echo {
                identifier: 123,
                sequence: 9,
                ..
            }
        ));
    }
}
