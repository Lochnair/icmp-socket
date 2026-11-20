# Changelog

## 0.6.6

- Apply the IPv4 TTL and IPv6 hop limit when the socket is created and when `set_max_hops` is called, instead of with a `setsockopt` before every send. A value the kernel rejects is retried on the next send, which reports the error. Clones of one OS socket now share the setting; the last `set_max_hops` wins.
- Serialize outgoing packets into a buffer reused by each socket instead of allocating per send. Datagram echo requests are encoded straight from the payload, so Tokio `poll_send` no longer copies it.
- Add `write_bytes` to `Icmpv4Packet`, `Icmpv6Packet`, `Icmpv4Message` and `Icmpv6Message` to append wire bytes to a caller's buffer.

## 0.6.5

- Add nonblocking Tokio raw and datagram ICMPv4 send polling and metadata receive polling. Polls bound immediate retry work; successful sends return the accepted byte count. Existing async send and metadata receive methods reuse the polling implementation.
- Add Linux raw ICMPv4 and ICMPv6 receive type filters, including access from async socket adapters.
- Keep the default build runtime-free. Polling operations use caller-owned deadlines; existing async receive timeout behavior is unchanged.
