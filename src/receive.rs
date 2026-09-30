use std::{io, time::Instant};

use socket2::{SockAddr, Socket};

pub(crate) struct ReceivedBytes {
    pub(crate) len: usize,
    pub(crate) peer: SockAddr,
    pub(crate) received_at: Instant,
    pub(crate) kernel_rx_timestamp: Option<std::time::SystemTime>,
    pub(crate) truncated: bool,
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io::{self, IoSliceMut},
        net::SocketAddr,
        os::fd::AsRawFd,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use nix::sys::{
        socket::{
            ControlMessageOwned, MsgFlags, SockaddrStorage, TimestampingFlag, Timestamps,
            cmsg_space, recvmsg, setsockopt, sockopt,
        },
        time::TimeSpec,
    };
    use socket2::{SockAddr, Socket};

    use super::ReceivedBytes;

    const RX_TIMESTAMPING_FLAGS: TimestampingFlag = TimestampingFlag::SOF_TIMESTAMPING_RX_SOFTWARE
        .union(TimestampingFlag::SOF_TIMESTAMPING_SOFTWARE);
    const CONTROL_LEN: usize = cmsg_space::<Timestamps>();

    #[repr(align(8))]
    struct ControlBuffer([u8; CONTROL_LEN]);

    pub(super) fn configure(socket: &Socket) {
        let _ = setsockopt(socket, sockopt::Timestamping, &RX_TIMESTAMPING_FLAGS);
    }

    pub(super) fn receive(socket: &Socket, buffer: &mut Vec<u8>) -> io::Result<ReceivedBytes> {
        let capacity = buffer.capacity();
        buffer.resize(capacity, 0);

        let mut control = ControlBuffer([0; CONTROL_LEN]);
        let mut iov = [IoSliceMut::new(buffer.as_mut_slice())];
        let message = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control.0),
            MsgFlags::empty(),
        )?;
        let received_at = Instant::now();
        let len = message.bytes;
        let truncated = message.flags.contains(MsgFlags::MSG_TRUNC) || len >= capacity;
        let peer = message
            .address
            .as_ref()
            .and_then(peer_address)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing ICMP peer address")
            })?;
        let kernel_rx_timestamp = receive_timestamp(&message);
        buffer.truncate(len.min(capacity));

        Ok(ReceivedBytes {
            len,
            peer,
            received_at,
            kernel_rx_timestamp,
            truncated,
        })
    }

    fn peer_address(address: &SockaddrStorage) -> Option<SockAddr> {
        let peer = address
            .as_sockaddr_in()
            .map(|addr| SocketAddr::from(*addr))
            .or_else(|| {
                address
                    .as_sockaddr_in6()
                    .map(|addr| SocketAddr::from(*addr))
            })?;
        Some(SockAddr::from(peer))
    }

    fn receive_timestamp<S>(message: &nix::sys::socket::RecvMsg<'_, '_, S>) -> Option<SystemTime> {
        let cmsgs = message.cmsgs().ok()?;
        for cmsg in cmsgs {
            if let ControlMessageOwned::ScmTimestampsns(timestamps) = cmsg {
                return system_time_from_timespec(timestamps.system);
            }
        }
        None
    }

    fn system_time_from_timespec(timespec: TimeSpec) -> Option<SystemTime> {
        let seconds = u64::try_from(timespec.tv_sec()).ok()?;
        let nanos = u32::try_from(timespec.tv_nsec()).ok()?;
        if nanos >= 1_000_000_000 {
            return None;
        }
        UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
    }
}

#[cfg(not(target_os = "linux"))]
mod other {
    use std::{io, time::Instant};

    use socket2::Socket;

    use super::ReceivedBytes;

    pub(super) fn configure(_: &Socket) {}

    pub(super) fn receive(socket: &Socket, buffer: &mut Vec<u8>) -> io::Result<ReceivedBytes> {
        buffer.clear();
        let (len, peer) = socket.recv_from(buffer.spare_capacity_mut())?;
        let received_at = Instant::now();
        let truncated = len >= buffer.capacity();
        unsafe {
            buffer.set_len(len);
        }
        Ok(ReceivedBytes {
            len,
            peer,
            received_at,
            kernel_rx_timestamp: None,
            truncated,
        })
    }
}

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(not(target_os = "linux"))]
use other as platform;

pub(crate) fn configure(socket: &Socket) {
    platform::configure(socket);
}

pub(crate) fn receive(socket: &Socket, buffer: &mut Vec<u8>) -> io::Result<ReceivedBytes> {
    platform::receive(socket, buffer)
}
