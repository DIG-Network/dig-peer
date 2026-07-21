# dig-peer — normative specification

`dig-peer` is the DIG Network peer **client**: the one abstraction a consumer uses to connect to a
DIG Network peer, call it over typed RPC, and disconnect. It is the client mirror of `dig-rpc`'s
server. This document is the authoritative contract an independent reimplementation could be built
against.

## 1. Scope and identity

- **DigPeer connects to DIG Network peers** (dig-node peers) over `dig-nat` mutual TLS + the
  `dig-rpc-protocol` wire. It wraps a `dig_nat::PeerConnection` (point-to-point). It is NOT the
  `dig-gossip` mesh/broadcast layer, and it is NOT `ChiaPeer` (the Chia full-node client) — it pulls
  in no Chia full-node protocol.
- **Hierarchy: L20** (`20-domain/dig-peer`). Dependencies are all strictly lower: `dig-nat` (L10),
  `dig-message` (L10), `dig-rpc-protocol` (L00), `dig-tls` (L00). No git dependencies; every dep is a
  crates.io release.

## 2. Connection

### 2.1 The connect ladder

`DigPeer::connect(peer, tls)` MUST establish a mutually-authenticated (mTLS) connection to `peer`.
The full traversal ladder is owned by `dig-nat` and MUST NOT be re-implemented here:

- `DigPeer::connect(peer, tls)` drives the **Direct** tier (the convenience entry point for a
  publicly-reachable peer / loopback).
- `DigPeer::connect_with_runtime(peer, tls, config, runtime)` auto-composes the **full** ladder —
  direct → UPnP → NAT-PMP → PCP → hole-punch → relayed, first-success-wins, IPv6-first at every
  IP-dialing tier (§5.2) — from the caller-supplied `NatRuntime` handles. The caller never chooses the
  method.
- Every tier — including the relayed one — runs the SAME `dig-tls` mTLS: the CA-chained `NodeCert`,
  the `peer_id` pin, and the #1204 BLS binding. A relayed connection is not weaker.

### 2.2 peer_id pinning (security, MUST)

`connect` MUST pin the mTLS handshake to `PeerTarget::peer_id` (via `dig-nat` / `dig-tls`). Chaining
to the DigNetwork CA authorizes *a* DIG peer, never a *specific* one. Therefore:

- A caller that means to reach peer X MUST supply X's `peer_id`. Connecting with a `peer_id` the
  answering peer does not present MUST fail (`DigPeerError::Transport`). This is enforced by the
  `dig-tls` client verifier, not advisory.

### 2.3 Captured identity

On a successful connect, dig-peer MUST record, from the verified handshake: the remote `peer_id`
(== the requested one) and the peer's BLS-G1 identity public key (`peer_bls_pub`), when the handshake
carried a valid #1204 binding. `peer_bls_pub` is the seal target (§4); it is `None` for a
legacy/unbound peer.

## 3. Typed RPC transport

### 3.1 On-stream framing (normative)

Each RPC call MUST open ONE fresh multiplexed logical stream (`dig_nat::PeerConnection::open_stream`),
write exactly one length-prefixed request body, read exactly one length-prefixed response body, and
let the stream close. Framing is a `u32` big-endian length prefix followed by that many body bytes —
identical to `dig-nat`'s control framing. A body length exceeding `MAX_BODY` (64 KiB) MUST be rejected
before allocation.

- **Unsealed body** — the JSON of a `dig_rpc_protocol::JsonRpcRequest` / `JsonRpcResponse`.
- **Sealed body** — the byte-serialized sealed `dig_message` envelope wrapping that JSON (§4).

### 3.2 Method classification

- **Public-read (unsealed):** `dig.health`, `dig.methods`, `dig.getAvailability`, byte-range fetch.
  These carry public-by-nature, merkle-verified content and ride mTLS unsealed (§5.4 sensible-scope
  exemption). `getAvailability` and range fetch delegate to the `dig-nat` mux primitives
  (`query_availability` / `open_range_stream`).
- **Directed (sealed §5.4):** `dig.getNetworkInfo`, `dig.getPeers`, `dig.announce`. These carry
  peer-specific content and MUST be sealed to the peer's `peer_bls_pub`.

### 3.3 Response decoding

A JSON-RPC error envelope MUST map to `DigPeerError::Rpc` carrying the peer's `RpcError` verbatim. A
body that is neither `result` nor `error` MUST be a `DigPeerError::Codec` failure, never a silent
success.

### 3.4 Raw-stream escape hatch (`open_stream`, unsealed)

`DigPeer::open_stream()` MUST open ONE fresh multiplexed logical stream over the
already-established mTLS `PeerConnection` (the same `dig_nat::PeerConnection::open_stream` path §3.1
rides) and return it as an opaque `dig_nat::PeerStream` (re-exported from the crate root) for the
caller to read/write directly. It performs NO framing, NO JSON encoding, and NO sealing — the bytes on
the wire are entirely the caller's own wire format.

- **Purpose.** It is the escape hatch for a consumer that carries its OWN wire framing rather than
  dig-peer's typed RPC methods — e.g. a same-level (L20) crate such as `dig-dht`, whose `DhtRequest`
  dig-peer MUST NOT typed-wrap (a same-level dependency is forbidden by the reference-down-only crate
  hierarchy). The caller owns `encode`/`decode`; dig-peer sees opaque bytes.
- **Unsealed, by design.** The stream rides the authenticated mTLS connection with NO auth bypass, but
  is NOT end-to-end sealed — consistent with `fetch_range` / content, DISTINCT from the sealed directed
  methods (§4). A caller placing recipient-specific secret content on this stream is responsible for
  its own §5.4 sealing; dig-peer does not seal it. Directed/secret messages MUST use the sealed typed
  methods, never this escape hatch.
- **Lifecycle.** MUST fail `DigPeerError::InvalidState` after `disconnect` (§5); MUST surface a stream
  failure as `DigPeerError::Io`.

## 4. The §5.4 directed-message seal

A directed RPC MUST be end-to-end sealed to the peer's BLS-G1 identity, layered ON TOP of mTLS, so an
intermediary that terminates TLS (a relay, a hole-punch forwarder) sees only ciphertext.

### 4.1 Composition

Sealing MUST use `dig-message`'s `seal_message` / `open_message` (DHKEM-over-G1 auth-seal + BLS-G2
sender signature + anti-replay). dig-peer MUST NOT invent crypto primitives.

- **Identity model:** the sealing identity is this node's BLS-G1 machine identity — the same key that
  signed its mTLS cert binding. The seal's DID fields use each peer's `peer_id` (`SHA-256(SPKI DER)`,
  32 bytes) as the `Bytes32` identity id; the receiver resolves the sender's BLS key from the binding
  it captured for that same connection.
- **Sender → recipient:** a request is sealed with `sender = local peer_id`, `recipient = peer
  peer_id`, `recipient_pub = captured peer_bls_pub`, signed by the local BLS secret key. The response
  is sealed by the peer to the local BLS key and MUST echo the request's `correlation_id`.

### 4.2 Fail-closed (MUST)

- A directed call with NO verified `peer_bls_pub` MUST fail `DigPeerError::PeerNotSealable` — never
  downgraded to an unsealed send.
- A directed call with no configured local sealing identity MUST fail
  `DigPeerError::NoSealingIdentity`.
- A response that fails authenticated-open / signature / replay / freshness MUST fail
  `DigPeerError::Seal`; a response whose `correlation_id` does not match the request MUST fail
  `DigPeerError::Misdelivered`. Neither surfaces unverified bytes.

## 5. Lifecycle

A connected peer is in state `Connected`. `disconnect(self)` moves it to `Closed` terminally and
drops the underlying session (closing the mux driver + the mTLS byte stream). Any RPC issued after
disconnect MUST fail `DigPeerError::InvalidState`. Because `disconnect` takes `self`, use-after-close
is additionally prevented at the type level.

## 6. Conformance

Cross-references: `SYSTEM.md` (the byte-identical relay-wire + seal contracts), the docs.dig.net "L7
· DIG Node peer network" protocol pages, `dig-rpc-protocol/SPEC.md` (the wire contract), and
CLAUDE.md §5.2 (IPv6-first), §5.3 (client→node mTLS ladder), §5.4 (directed-message e2e seal).
