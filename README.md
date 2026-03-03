# ICMP Sockets for both IPv4 and IPv6

**This is a fork of [zaphar/icmp-socket](https://github.com/zaphar/icmp-socket).**

### Major Changes Since Fork

- Added timestamp request/reply support
- Added `with_echo_reply` for IPv4 packets (@djackreuter)
- Added support for binding to a network interface (@timoschwarzer)
- Removed `byteorder` dependency
- Use `Vec::spare_capacity_mut` instead of unsafe buffer initialization

An implementation of ICMP Sockets for both IPv4 and IPv6.

Sockets can be created from IP addresses. IPv4 addresses will construct ICMP4 sockets. IPv6 will construct ICMP6 sockets.

```rust
let parsed_addr = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
let socket = IcmpSocket4::try_from(parsed_addr).unwrap();
```

It can construct and parse the common ICMP packets for both ICMP4 and ICMP6.

```rust
let packet4 = Icmpv4Packet::with_echo_request(42, 1, "payload".to_bytes());
let packet6 = Icmpv6Packet::with_echo_request(42, 1, "payload".to_bytes());
```

# API Documentation

https://docs.rs/icmp-socket/0.2.0
