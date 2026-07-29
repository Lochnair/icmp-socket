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

## Async backends

Async ICMPv4 sockets use the same packet, checksum, bind, identifier, TTL,
buffer, truncation, and timeout semantics as the blocking sockets, with
backend-specific reactor integration:

- `async-io` enables the direct `async-io` backend formerly exposed as “smol”.
  Convert sockets with `into_async_io()`.
- `smol` is a backwards-compatible feature alias for `async-io`. Existing
  `icmp_socket2::smol` paths and `into_async()` calls continue to work without
  depending on the top-level `smol` crate.
- `tokio` enables a first-class Tokio backend on Unix. Convert sockets with
  `into_tokio()` from inside an entered Tokio runtime context.

The crate does not create or own a Tokio runtime. Tokio ICMP socket types are
currently omitted on non-Unix targets; enabling the feature there still
compiles the portable parts of the crate.

The `async-io` backend is reactor integration, not a complete runtime. It uses
`async-io` readiness and timers directly, while the Tokio backend uses Tokio's
`AsyncFd` readiness and timeout facilities.

# API Documentation

https://docs.rs/icmp-socket2
