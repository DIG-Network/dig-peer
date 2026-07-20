# dig-peer

The DIG Network peer **client** — the one abstraction every consumer uses to talk to a DIG Network
peer.

```rust,no_run
use std::sync::Arc;
use dig_peer::{DigPeer, PeerTarget, NodeCert, SealingIdentity};

# async fn run(node: Arc<NodeCert>, my_bls_key: dig_tls::bls::SecretKey, peer_id: dig_peer::PeerId, addr: std::net::SocketAddr) -> Result<(), dig_peer::DigPeerError> {
// Describe the peer once (its peer_id pins the mTLS identity), then connect.
let target = PeerTarget::with_addr(peer_id, addr, "DIG_MAINNET");
let mut peer = DigPeer::connect(&target, &node).await?;

// Public-read RPC — unsealed, rides mTLS.
let health = peer.health().await?;
println!("peer status: {}", health.status);

// Directed RPC — end-to-end sealed to the peer's BLS-G1 identity (§5.4). Needs a sealing identity.
let mut peer = peer.with_sealing_identity(SealingIdentity::new(my_bls_key, 0));
let info = peer.get_network_info().await?;
println!("peer network: {}", info.network_id);

peer.disconnect().await;
# Ok(()) }
```

## What it is

- **`DigPeer::connect(peer, tls)`** drives [`dig-nat`](https://crates.io/crates/dig-nat)'s full
  traversal ladder (direct → UPnP → NAT-PMP → PCP → hole-punch → relayed, IPv6-first) — the caller
  never chooses a transport — and returns a mutually-authenticated (mTLS) connection.
- **Typed RPC** over [`dig-rpc-protocol`](https://crates.io/crates/dig-rpc-protocol): `health`,
  `methods`, `get_network_info`, `get_peers`, `announce`, `get_availability`, `fetch_range`.
- **Directed calls are sealed** end-to-end to the peer's verified BLS-G1 identity
  ([`dig-message`](https://crates.io/crates/dig-message), §5.4) on top of mTLS — a relay that
  terminates TLS forwards ciphertext it cannot read. Fail-closed: never downgraded to plaintext.
- **`disconnect()`** cleanly tears the connection down.

## What it is NOT

- **Not a `ChiaPeer`** — DigPeer connects to DIG Network peers, not Chia full nodes. Zero Chia
  full-node protocol.
- **Not the mesh layer** — it wraps a point-to-point `dig_nat::PeerConnection`, not `dig-gossip`'s
  broadcast mesh.

## Security

Reaching a **specific** peer requires supplying that peer's `peer_id` — chaining to the DigNetwork CA
alone authorizes *a* DIG peer, never a *specific* one. This is enforced in the handshake, not
advisory. See [`SPEC.md`](SPEC.md) §2.2, §4.

## License

Apache-2.0 OR MIT.
