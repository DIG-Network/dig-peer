# Changelog

All notable changes to dig-peer are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-19

### Added
- Initial release of `dig-peer`, the DIG Network peer client (#1268).
- `DigPeer::connect` / `connect_with_runtime` — establishes a peer_id-pinned mTLS connection by
  driving `dig-nat`'s full direct→relay traversal ladder (IPv6-first).
- Typed RPC over `dig-rpc-protocol`: `health`, `methods`, `get_network_info`, `get_peers`,
  `announce`, `get_availability`, `fetch_range`.
- §5.4 recipient-seal on directed control RPCs via `dig-message` — sealed to the peer's captured
  BLS-G1 identity on top of mTLS, fail-closed when the peer is unbound or no sealing identity is set.
- `disconnect` clean teardown + a `Connected`/`Closed` lifecycle guarding against use-after-close.
