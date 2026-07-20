# dig-peer development log

Durable realizations from building dig-peer. Context, not a change diary.

## The peer-RPC on-stream framing is dig-peer's to define
`dig-rpc` is an HTTP/axum JSON-RPC *server*; it does NOT carry JSON-RPC over the dig-nat mux. dig-peer
defines the peer-stream framing (a `u32`-BE length prefix + body, matching dig-nat's own control
framing) and is the client that speaks it. A future dig-node peer-RPC *server* must read this same
framing. One request/response per fresh mux stream; concurrency comes from the mux.

## The §5.4 seal is node-machine-identity, not user-DID
DigPeer seals directed RPC with the node's BLS-G1 *machine* identity (the key that signed its mTLS
cert binding), not a user DID. The seal's `Bytes32` DID fields carry each peer's `peer_id`
(`SHA-256(SPKI DER)`); the receiver resolves the sender's BLS key from the cert binding it captured
at the handshake, so NO DID registry is needed for node↔node RPC. This keeps the node identity-
agnostic w.r.t. user keys (the node↔user-app identity boundary) while still binding confidentiality
to the recipient's key, not merely to the mTLS pipe.

## peer_id pin is the real authentication, CA-chain is not
Chaining to the DigNetwork CA authorizes *a* DIG peer, never a *specific* one (the CA + its key are
public). Reaching peer X requires supplying X's `peer_id` so the dig-tls client verifier pins it.
`connect(addr, tls)` alone (no peer_id) would be an impersonation footgun — hence the API takes a
`PeerTarget` carrying the peer_id.

## Availability / range reads are §5.4-exempt
`getAvailability` + byte-range fetch carry public-by-nature, merkle-verified content addressed to
everyone, so they ride mTLS unsealed (the §5.4 sensible-scope exemption) and delegate straight to the
dig-nat mux primitives. Only peer-specific control RPCs (getNetworkInfo/getPeers/announce) are sealed.
