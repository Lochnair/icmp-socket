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

## Linux receive filters

Raw sockets expose `set_allowed_types(&[u8])` on Linux. The kernel filters
incoming ICMP types before they enter the socket's receive queue:

```rust
use icmp_socket2::{IcmpSocket4, IcmpSocket6};

let socket4 = IcmpSocket4::new()?;
socket4.set_allowed_types(&[0, 14])?; // Echo Reply and Timestamp Reply
// Include errors when needed:
socket4.set_allowed_types(&[0, 3, 11, 12, 14])?;

let socket6 = IcmpSocket6::new()?;
socket6.set_allowed_types(&[129])?; // Echo Reply
socket6.set_allowed_types(&[1, 2, 3, 4, 129])?; // Also allow ICMPv6 errors

socket4.clear_type_filter()?; // Restore reception of all types
```

Each call replaces the allow-list; an empty list blocks every filterable type.
Linux's IPv4 `ICMP_FILTER` covers only types 0–31. Higher types always pass,
and listing one returns `InvalidInput` without changing the current filter.
IPv6's `ICMP6_FILTER` covers all 256 types.

Filters apply to packets arriving after configuration; queued packets remain.
They are shared by cloned handles and preserved by async conversions. Both raw
IPv4 async backends expose the same methods. Filtering does not select an
identifier or change the kernel's handling of ICMP. These methods are omitted
on non-Linux targets and on datagram ping sockets.

# API Documentation

https://docs.rs/icmp-socket2
