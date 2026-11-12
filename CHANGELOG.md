# Changelog

## 0.6.5

- Add nonblocking Tokio raw and datagram ICMPv4 send polling and metadata receive polling. Polls bound immediate retry work; successful sends return the accepted byte count. Existing async send and metadata receive methods reuse the polling implementation.
- Add Linux raw ICMPv4 and ICMPv6 receive type filters, including access from async socket adapters.
- Keep the default build runtime-free. Polling operations use caller-owned deadlines; existing async receive timeout behavior is unchanged.
