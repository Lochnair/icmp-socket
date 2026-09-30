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
//! On-the-wire smoke tests for the ICMP datagram receive paths.
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use icmp_socket2::*;
use socket2::SockAddr;

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

fn open_socket() -> Option<DgramIcmpSocket4> {
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping ICMP loopback test: could not open ping socket: {error}");
            return None;
        }
    };
    if let Err(error) = socket.bind(Ipv4Addr::UNSPECIFIED) {
        eprintln!("skipping ICMP loopback test: could not bind ping socket: {error}");
        return None;
    }
    socket.set_timeout(Some(Duration::from_secs(2)));
    Some(socket)
}

fn is_expected_reply(packet: &Icmpv4Packet, peer: &SockAddr, sequence: u16) -> bool {
    let from = *peer
        .as_socket_ipv4()
        .expect("reply was not an IPv4 address")
        .ip();
    if from != LOCALHOST {
        return false;
    }
    assert!(
        packet.verify_checksum(),
        "loopback reply failed checksum verification"
    );
    matches!(packet.message, Icmpv4Message::EchoReply { sequence: value, .. } if value == sequence)
}

#[test]
#[ignore]
fn dgram_loopback_roundtrip() {
    let Some(mut socket) = open_socket() else {
        return;
    };
    if let Err(error) = socket.send(LOCALHOST, 1, vec![0x20; 16]) {
        eprintln!("skipping ICMP loopback test: could not send ping: {error}");
        return;
    }

    loop {
        let (packet, peer) = socket.rcv_from().expect("failed to receive a reply");
        if is_expected_reply(&packet, &peer, 1) {
            return;
        }
    }
}

#[test]
#[ignore]
fn dgram_loopback_roundtrip_with_meta() {
    let Some(mut socket) = open_socket() else {
        return;
    };
    socket
        .enable_receive_metadata()
        .expect("failed to enable receive metadata");
    if let Err(error) = socket.send(LOCALHOST, 2, vec![0x20; 16]) {
        eprintln!("skipping ICMP loopback test: could not send ping: {error}");
        return;
    }

    loop {
        let received = socket
            .rcv_from_with_meta()
            .expect("failed to receive a reply with metadata");
        if is_expected_reply(&received.packet, &received.peer, 2) {
            assert!(received.received_at <= Instant::now());
            #[cfg(target_os = "linux")]
            assert!(
                received.kernel_rx_timestamp.is_some(),
                "Linux did not provide SCM_TIMESTAMPING"
            );
            return;
        }
    }
}

#[cfg(feature = "async-io")]
#[test]
#[ignore]
fn async_io_dgram_loopback_roundtrip_with_meta() {
    futures_lite::future::block_on(async {
        let Some(socket) = open_socket() else {
            return;
        };
        let mut socket = socket
            .into_async_io()
            .expect("failed to create async socket");
        socket
            .enable_receive_metadata()
            .expect("failed to enable receive metadata");
        socket
            .send(LOCALHOST, 3, vec![0x20; 16])
            .await
            .expect("failed to send ping after socket setup");
        loop {
            let received = socket
                .rcv_from_with_meta()
                .await
                .expect("failed to receive an async reply with metadata");
            if is_expected_reply(&received.packet, &received.peer, 3) {
                assert!(received.received_at <= Instant::now());
                return;
            }
        }
    });
}

#[cfg(all(feature = "tokio", unix))]
#[test]
#[ignore]
fn tokio_dgram_loopback_roundtrip_with_meta() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");
    runtime.block_on(async {
        let Some(socket) = open_socket() else {
            return;
        };
        let mut socket = socket.into_tokio().expect("failed to create Tokio socket");
        socket
            .enable_receive_metadata()
            .expect("failed to enable receive metadata");
        socket
            .send(LOCALHOST, 4, vec![0x20; 16])
            .await
            .expect("failed to send ping after socket setup");
        loop {
            let received = socket
                .rcv_from_with_meta()
                .await
                .expect("failed to receive a Tokio reply with metadata");
            if is_expected_reply(&received.packet, &received.peer, 4) {
                assert!(received.received_at <= Instant::now());
                return;
            }
        }
    });
}

#[test]
#[ignore]
fn dgram_recv_buffer_truncation() {
    let Some(mut socket) = open_socket() else {
        return;
    };
    socket.set_read_buffer_size(8);
    socket
        .send(LOCALHOST, 5, vec![0x20; 32])
        .expect("failed to send");
    let err = socket
        .rcv_from()
        .expect_err("expected a truncation error with an 8 byte buffer");
    assert!(err.to_string().contains("truncat"));

    socket.set_read_buffer_size(2048);
    socket
        .send(LOCALHOST, 6, vec![0x20; 32])
        .expect("failed to send");
    loop {
        let (packet, peer) = socket.rcv_from().expect("failed to receive a reply");
        if is_expected_reply(&packet, &peer, 6) {
            return;
        }
    }
}
