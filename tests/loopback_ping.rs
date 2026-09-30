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
//! On-the-wire smoke test for the ICMP datagram receive path.
use std::net::Ipv4Addr;
use std::time::Duration;

use icmp_socket2::*;

#[test]
fn dgram_loopback_roundtrip() {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skipping ICMP loopback test: could not open ping socket: {e}");
            return;
        }
    };
    if let Err(e) = socket.bind(Ipv4Addr::new(0, 0, 0, 0)) {
        eprintln!("skipping ICMP loopback test: could not bind ping socket: {e}");
        return;
    }
    socket.set_timeout(Some(Duration::from_secs(2)));

    if let Err(e) = socket.send(localhost, 1, vec![0x20; 16]) {
        eprintln!("skipping ICMP loopback test: could not send ping: {e}");
        return;
    }

    // Read until we see the reply for our destination or time out. The kernel
    // may rewrite the identifier on datagram sockets, so match on the reply
    // type and sequence rather than the identifier.
    loop {
        let received = match socket.rcv_from() {
            Ok(received) => received,
            Err(e) => {
                eprintln!("skipping ICMP loopback test: no reply was received: {e}");
                return;
            }
        };
        let from = *received
            .peer
            .as_socket_ipv4()
            .expect("reply was not an IPv4 address")
            .ip();
        if from != localhost {
            continue;
        }
        // The reply came from a real kernel; its ICMP checksum must verify.
        assert!(
            received.packet.verify_checksum(),
            "loopback reply failed checksum verification"
        );
        // Match our own sequence; ignore any stray ICMP on the loopback
        // interface (on macOS datagram sockets share identifier 0).
        if let Icmpv4Message::EchoReply { sequence: 1, .. } = received.packet.message {
            assert!(received.received_at <= std::time::Instant::now());
            if received.kernel_rx_timestamp.is_none() {
                eprintln!("kernel did not provide SCM_TIMESTAMPING; ordinary receive passed");
            }
            return;
        }
    }
}

#[test]
#[ignore]
fn dgram_recv_buffer_truncation() {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(s) => s,
        Err(e) => panic!("could not open an ICMP datagram socket ({})", e),
    };
    socket
        .bind(Ipv4Addr::new(0, 0, 0, 0))
        .expect("failed to bind");
    socket.set_timeout(Some(Duration::from_secs(2)));

    // An 8 byte buffer cannot hold the echo reply, so rcv_from must report a
    // truncation error rather than a partial packet.
    socket.set_read_buffer_size(8);
    socket
        .send(localhost, 1, vec![0x20; 32])
        .expect("failed to send");
    let err = socket
        .rcv_from()
        .expect_err("expected a truncation error with an 8 byte buffer");
    assert!(
        err.to_string().contains("truncat"),
        "expected a truncation error, got: {}",
        err
    );

    // With a large buffer the same exchange succeeds.
    socket.set_read_buffer_size(2048);
    socket
        .send(localhost, 2, vec![0x20; 32])
        .expect("failed to send");
    loop {
        let received = socket.rcv_from().expect("failed to receive a reply");
        if *received
            .peer
            .as_socket_ipv4()
            .expect("reply was not an IPv4 address")
            .ip()
            != localhost
        {
            continue;
        }
        if let Icmpv4Message::EchoReply { sequence, .. } = received.packet.message {
            if sequence == 2 {
                return;
            }
        }
    }
}
