//! Kernel receive-filter tests. Run with root or CAP_NET_RAW on Linux.
#![cfg(target_os = "linux")]

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use icmp_socket2::{
    IcmpSocket, IcmpSocket4, IcmpSocket6, Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet,
    packet::{
        WithEchoRequest, WithParameterProblem, WithTimeExceeded, WithTimestampReply,
        WithUnreachable,
    },
};

const TIMEOUT: Duration = Duration::from_millis(200);
const IDENTIFIER: u16 = 0x4f17;

fn echo4() -> Icmpv4Packet {
    Icmpv4Packet::with_echo_request(IDENTIFIER, 1, vec![0x42; 16]).unwrap()
}

fn echo6() -> Icmpv6Packet {
    Icmpv6Packet::with_echo_request(IDENTIFIER, 1, vec![0x42; 16]).unwrap()
}

fn assert_timeout<T: std::fmt::Debug>(result: io::Result<T>) {
    let error = result.expect_err("a blocked ICMP packet reached the socket");
    assert!(matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut
    ));
}

#[test]
#[ignore = "requires root or CAP_NET_RAW"]
fn ipv4_filter_replies_errors_replacement_and_clones() -> io::Result<()> {
    let mut receiver = IcmpSocket4::try_from(Ipv4Addr::LOCALHOST)?;
    receiver.set_timeout(Some(TIMEOUT));
    let mut sender = IcmpSocket4::try_from(Ipv4Addr::LOCALHOST)?;

    receiver.set_allowed_types(&[0, 3, 11, 12, 14, 31, 0])?;
    // Reject the whole update, including any valid types preceding the error.
    for invalid in [&[8, 32][..], &[255][..]] {
        assert_eq!(
            receiver.set_allowed_types(invalid).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
    sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
    let received = receiver.rcv_from()?.0;
    assert_eq!(received.typ, 0); // The request (8) must have been filtered.
    assert!(received.verify_checksum());
    assert_timeout(receiver.rcv_from());

    for packet in [
        Icmpv4Packet::with_timestamp_reply(IDENTIFIER, 1, 0, 0, 0).unwrap(),
        Icmpv4Packet::with_unreachable(0, vec![0; 28]).unwrap(),
        Icmpv4Packet::with_time_exceeded(0, vec![0; 28]).unwrap(),
        Icmpv4Packet::with_parameter_problem(0, 17, vec![0x42; 28]).unwrap(),
    ] {
        let expected_type = packet.typ;
        sender.send_to(Ipv4Addr::LOCALHOST, packet)?;
        let received = receiver.rcv_from()?.0;
        assert_eq!(received.typ, expected_type);
        assert!(received.verify_checksum());
        if expected_type == 12 {
            assert!(matches!(
                received.message,
                Icmpv4Message::ParameterProblem {
                    pointer: 17,
                    padding: (0, 0),
                    header,
                } if header == vec![0x42; 28]
            ));
        }
    }

    receiver.set_allowed_types(&[])?;
    sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
    assert_timeout(receiver.rcv_from());

    let clone = receiver.try_clone()?;
    clone.set_allowed_types(&[8])?;
    sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
    assert_eq!(receiver.rcv_from()?.0.typ, 8);
    assert_timeout(receiver.rcv_from());

    clone.clear_type_filter()?;
    sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
    assert_eq!(receiver.rcv_from()?.0.typ, 8);
    assert_eq!(receiver.rcv_from()?.0.typ, 0);
    Ok(())
}

#[test]
#[ignore = "requires root or CAP_NET_RAW and IPv6 loopback"]
fn ipv6_filter_multiple_words_replacement_and_clones() -> io::Result<()> {
    let mut receiver = IcmpSocket6::try_from(Ipv6Addr::LOCALHOST)?;
    receiver.set_timeout(Some(TIMEOUT));
    let mut sender = IcmpSocket6::try_from(Ipv6Addr::LOCALHOST)?;

    receiver.set_allowed_types(&[1, 2, 3, 4, 31, 32, 63, 64, 127, 129, 200, 255, 129])?;
    sender.send_to(Ipv6Addr::LOCALHOST, echo6())?;
    let received = receiver.rcv_from()?.0;
    assert_eq!(received.typ, 129); // The request (128) must have been filtered.
    assert!(received.verify_checksum(&Ipv6Addr::LOCALHOST, &Ipv6Addr::LOCALHOST));
    assert_timeout(receiver.rcv_from());

    for packet in [
        Icmpv6Packet::with_unreachable(0, vec![0; 48]).unwrap(),
        Icmpv6Packet::with_packet_too_big(1280, vec![0; 48]).unwrap(),
        Icmpv6Packet::with_time_exceeded(0, vec![0; 48]).unwrap(),
        Icmpv6Packet::with_parameter_problem(0, 0, vec![0; 48]).unwrap(),
        Icmpv6Packet {
            typ: 200,
            code: 0,
            checksum: 0,
            message: Icmpv6Message::PrivateExperimental {
                padding: 0,
                payload: vec![0x42; 16],
            },
        },
    ] {
        let expected_type = packet.typ;
        sender.send_to(Ipv6Addr::LOCALHOST, packet)?;
        let received = receiver.rcv_from()?.0;
        assert_eq!(received.typ, expected_type);
        assert!(received.verify_checksum(&Ipv6Addr::LOCALHOST, &Ipv6Addr::LOCALHOST));
    }

    receiver.set_allowed_types(&[])?;
    sender.send_to(Ipv6Addr::LOCALHOST, echo6())?;
    assert_timeout(receiver.rcv_from());

    let clone = receiver.try_clone()?;
    clone.set_allowed_types(&[128])?;
    sender.send_to(Ipv6Addr::LOCALHOST, echo6())?;
    assert_eq!(receiver.rcv_from()?.0.typ, 128);
    assert_timeout(receiver.rcv_from());

    clone.clear_type_filter()?;
    sender.send_to(Ipv6Addr::LOCALHOST, echo6())?;
    assert_eq!(receiver.rcv_from()?.0.typ, 128);
    assert_eq!(receiver.rcv_from()?.0.typ, 129);
    Ok(())
}

#[cfg(feature = "async-io")]
#[test]
#[ignore = "requires root or CAP_NET_RAW"]
fn async_io_filter_survives_conversion_and_can_be_updated() -> io::Result<()> {
    use icmp_socket2::AsyncIcmpSocket;

    futures_lite::future::block_on(async {
        let mut receiver = IcmpSocket4::try_from(Ipv4Addr::LOCALHOST)?;
        receiver.set_timeout(Some(TIMEOUT));
        receiver.set_allowed_types(&[0])?;
        let mut receiver = receiver.into_async_io()?;
        let mut sender = IcmpSocket4::try_from(Ipv4Addr::LOCALHOST)?;

        sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
        assert_eq!(receiver.rcv_from().await?.0.typ, 0);
        assert_timeout(receiver.rcv_from().await);

        receiver.set_allowed_types(&[])?;
        sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
        assert_timeout(receiver.rcv_from().await);

        receiver.clear_type_filter()?;
        sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
        assert_eq!(receiver.rcv_from().await?.0.typ, 8);
        assert_eq!(receiver.rcv_from().await?.0.typ, 0);
        Ok(())
    })
}

#[cfg(feature = "tokio")]
#[test]
#[ignore = "requires root or CAP_NET_RAW"]
fn tokio_filter_survives_conversion_and_can_be_updated() -> io::Result<()> {
    use icmp_socket2::AsyncIcmpSocket;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut receiver = IcmpSocket4::try_from(Ipv4Addr::LOCALHOST)?;
        receiver.set_timeout(Some(TIMEOUT));
        receiver.set_allowed_types(&[0])?;
        let mut receiver = receiver.into_tokio()?;
        let mut sender = IcmpSocket4::try_from(Ipv4Addr::LOCALHOST)?;

        sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
        assert_eq!(receiver.rcv_from().await?.0.typ, 0);
        assert_timeout(receiver.rcv_from().await);

        receiver.set_allowed_types(&[])?;
        sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
        assert_timeout(receiver.rcv_from().await);

        receiver.clear_type_filter()?;
        sender.send_to(Ipv4Addr::LOCALHOST, echo4())?;
        assert_eq!(receiver.rcv_from().await?.0.typ, 8);
        assert_eq!(receiver.rcv_from().await?.0.typ, 0);
        Ok(())
    })
}
