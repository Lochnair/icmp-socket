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
//! Async ICMPv4 ping example using the Unix Tokio backend.
#[cfg(unix)]
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

#[cfg(unix)]
use icmp_socket2::*;

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_owned());
    let parsed_addr = address
        .parse::<Ipv4Addr>()
        .expect("argument must be an IPv4 address");
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // `into_tokio` is deliberately called inside the entered runtime
        // context because AsyncFd registration requires it.
        let mut socket = DgramIcmpSocket4::new()?.into_tokio()?;
        socket.bind(Ipv4Addr::new(0, 0, 0, 0)).await?;
        socket.set_timeout(Some(Duration::from_secs(1)));

        let mut sequence = 0u16;
        loop {
            let send_time = Instant::now();
            socket
                .send(
                    parsed_addr,
                    sequence,
                    vec![
                        0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73,
                        0x68, 0x20, 0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73,
                        0x20, 0x62, 0x75, 0x74, 0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74,
                        0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20,
                        0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
                    ],
                )
                .await?;

            loop {
                match socket.rcv_from().await {
                    Ok((resp, sock_addr)) => {
                        let addr = match sock_addr.as_socket_ipv4() {
                            Some(a) => *a.ip(),
                            None => continue,
                        };
                        if addr != parsed_addr {
                            continue;
                        }
                        if !resp.verify_checksum() {
                            eprintln!("Discarding packet with invalid checksum");
                            continue;
                        }
                        if let Icmpv4Message::EchoReply {
                            sequence: seq,
                            payload,
                            ..
                        } = resp.message
                        {
                            let elapsed = Instant::now() - send_time;
                            println!(
                                "Ping {} seq={} time={}ms size={}",
                                addr,
                                seq,
                                (elapsed.as_micros() as f64) / 1000.0,
                                payload.len()
                            );
                            break;
                        }
                    }
                    Err(error) => {
                        eprintln!("{error:?}");
                        break;
                    }
                }
            }
            ::tokio::time::sleep(Duration::from_secs(1)).await;
            sequence = sequence.wrapping_add(1);
        }
    })
}

#[cfg(not(unix))]
fn main() {
    eprintln!("the Tokio ICMP backend is currently available only on Unix");
}
