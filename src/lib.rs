//! # dig-peer — the DIG Network peer client
//!
//! [`DigPeer`] is the one client every consumer uses to talk to a DIG Network peer. You describe the
//! peer once ([`PeerTarget`]) and get back a connected [`DigPeer`]; it drives [`dig-nat`](dig_nat)'s
//! full traversal ladder (direct → UPnP → NAT-PMP → PCP → hole-punch → relayed, IPv6-first) under the
//! hood, so the caller never chooses a transport. On top of that mutually-authenticated (mTLS)
//! connection it exposes **typed RPC** over [`dig-rpc-protocol`](dig_rpc_protocol) and seals
//! **directed** calls end-to-end to the peer's verified BLS-G1 identity (§5.4). [`DigPeer::disconnect`]
//! tears the connection down cleanly.
//!
//! dig-peer is the **client mirror** of `dig-rpc`'s server. It wraps a [`dig_nat::PeerConnection`]
//! (point-to-point) — NOT `dig-gossip`, which is the mesh/broadcast layer. It is also **not** a
//! `ChiaPeer`: DigPeer connects to DIG Network peers over dig-nat mTLS + dig-rpc-protocol; it pulls in
//! zero Chia full-node protocol.
//!
//! ## Reaching a SPECIFIC peer requires its `peer_id` (security)
//!
//! [`DigPeer::connect`] takes a [`PeerTarget`] carrying the peer's **`peer_id`** (`SHA-256(SPKI DER)`)
//! and pins the mTLS handshake to it (via dig-nat / dig-tls). Chaining to the DigNetwork CA alone
//! authorizes *a* DIG peer, never a *specific* one — so a caller that means to reach peer X MUST
//! supply X's `peer_id`, or a different CA-valid peer could answer in its place. This is enforced, not
//! advisory: connect fails if the peer that answers does not present the expected `peer_id`.
//!
//! ## Directed calls are sealed, fail-closed (§5.4)
//!
//! Control RPCs that carry peer-specific content (`getNetworkInfo`, `getPeers`, `announce`) are
//! DIRECTED: dig-peer seals their payload to the peer's captured BLS-G1 key before sending, so an
//! intermediary that terminates TLS (a relay) forwards ciphertext it cannot read. A directed call is
//! **refused** (never downgraded to plaintext) if the peer presented no verified BLS-G1 key or no
//! local sealing identity is configured — set one with [`DigPeer::with_sealing_identity`].
//!
//! Public-read/availability calls (`health`, `getAvailability`, byte-range fetch) carry
//! public-by-nature, merkle-verified content and are NOT directed (§5.4 sensible-scope exemption):
//! they ride mTLS unsealed.
//!
//! ## Example
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use dig_peer::{DigPeer, PeerTarget, NodeCert, PeerId};
//! # async fn run(node: Arc<NodeCert>, peer_id: PeerId, addr: std::net::SocketAddr) -> Result<(), dig_peer::DigPeerError> {
//! let target = PeerTarget::with_addr(peer_id, addr, "DIG_MAINNET");
//! let mut peer = DigPeer::connect(&target, &node).await?;
//! let health = peer.health().await?;
//! println!("peer status: {}", health.status);
//! peer.disconnect().await;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod rpc;
pub mod seal;
pub mod state;

use std::sync::Arc;

use dig_nat::{connect_with_runtime, NatConfig, NatRuntime, PeerConnection, PeerId as NatPeerId};
use dig_rpc_protocol::envelope::{JsonRpcRequest, RequestId};
use dig_rpc_protocol::types::{
    AnnounceAck, AnnounceParams, Health, Methods, NetworkInfo, PeersList,
};
use dig_rpc_protocol::{JsonRpcResponse, Method};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub use dig_nat::{AvailabilityItem, AvailabilityResponse, PeerTarget, RangeRequest};
pub use dig_tls::{NodeCert, PeerId};

pub use error::{DigPeerError, Result};
pub use seal::SealingIdentity;
pub use state::PeerState;

/// A connected DIG Network peer — the client every consumer uses.
///
/// Obtain one with [`DigPeer::connect`]. It owns the underlying mTLS [`PeerConnection`], the local and
/// remote `peer_id`s, the peer's captured BLS-G1 key (the seal target), and an optional
/// [`SealingIdentity`] for directed calls. Each RPC opens a fresh multiplexed stream, so calls are
/// naturally concurrent-safe against the mux; the `&mut self` receiver serializes them per client.
pub struct DigPeer {
    /// This node's own `peer_id` — the sender identity for directed seals.
    local_peer_id: PeerId,
    /// The verified remote `peer_id` (== the [`PeerTarget::peer_id`] asked for).
    peer_id: PeerId,
    /// The peer's verified BLS-G1 identity (48-byte compressed), captured from the cert binding.
    /// `None` for a legacy/unbound peer — directed sealed calls are then refused (fail-closed).
    peer_bls_pub: Option<[u8; 48]>,
    /// The multiplexed mTLS connection.
    conn: PeerConnection,
    /// The local sealing identity for directed calls; `None` until [`Self::with_sealing_identity`].
    sealing: Option<SealingIdentity>,
    /// The connection lifecycle state.
    state: PeerState,
    /// The next JSON-RPC request id.
    next_id: u64,
}

impl std::fmt::Debug for DigPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigPeer")
            .field("peer_id", &self.peer_id)
            .field("state", &self.state)
            .field("sealable", &self.peer_bls_pub.is_some())
            .field("has_sealing_identity", &self.sealing.is_some())
            .finish()
    }
}

impl DigPeer {
    /// Connect to `peer`, driving the Direct traversal tier only (the convenience entry point for a
    /// publicly-reachable peer / loopback). A NAT'd peer needing the full ladder uses
    /// [`Self::connect_with_runtime`].
    ///
    /// `tls` is this node's mTLS [`NodeCert`]; the handshake pins the remote to
    /// [`PeerTarget::peer_id`] (see the crate-level security note). Captures the peer's BLS-G1 key for
    /// sealing.
    ///
    /// # Errors
    /// [`DigPeerError::Transport`] if the peer is unreachable or the `peer_id` pin fails.
    pub async fn connect(peer: &PeerTarget, tls: &Arc<NodeCert>) -> Result<Self> {
        Self::connect_with_runtime(peer, tls, &NatConfig::default(), &NatRuntime::default()).await
    }

    /// Connect to `peer`, auto-composing the **full** NAT-traversal ladder from `config` + the live
    /// `runtime` handles (direct → UPnP → NAT-PMP → PCP → hole-punch → relayed, IPv6-first). The
    /// caller never chooses the method — dig-nat picks the first tier that establishes a
    /// `peer_id`-verified mTLS connection.
    ///
    /// # Errors
    /// [`DigPeerError::Transport`] if no tier could be composed or every composed tier failed.
    pub async fn connect_with_runtime(
        peer: &PeerTarget,
        tls: &Arc<NodeCert>,
        config: &NatConfig,
        runtime: &NatRuntime,
    ) -> Result<Self> {
        let conn = connect_with_runtime(peer, tls, config, runtime).await?;
        Ok(Self::from_connection(tls.peer_id(), conn))
    }

    /// Wrap an already-established [`PeerConnection`] as a [`DigPeer`], recording this node's own
    /// `peer_id` (`local_peer_id`, the sender identity for directed seals).
    ///
    /// Useful for a serving node that accepted an inbound dig-nat connection and wants the typed-RPC
    /// client surface over it, without re-dialing.
    #[must_use]
    pub fn from_connection(local_peer_id: NatPeerId, conn: PeerConnection) -> Self {
        Self {
            local_peer_id,
            peer_id: conn.peer_id,
            peer_bls_pub: conn.peer_bls_pub,
            conn,
            sealing: None,
            state: PeerState::Connected,
            next_id: 1,
        }
    }

    /// Attach a [`SealingIdentity`] so this client can make **directed** (sealed) RPC calls. Without
    /// one, directed calls fail with [`DigPeerError::NoSealingIdentity`].
    #[must_use]
    pub fn with_sealing_identity(mut self, sealing: SealingIdentity) -> Self {
        self.sealing = Some(sealing);
        self
    }

    /// The verified remote `peer_id`.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The peer's verified BLS-G1 identity (the seal target), or `None` for an unbound peer.
    #[must_use]
    pub fn peer_bls_pub(&self) -> Option<[u8; 48]> {
        self.peer_bls_pub
    }

    /// The connection lifecycle state.
    #[must_use]
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Whether directed sealed RPC is possible right now (the peer is bound AND a sealing identity is
    /// configured).
    #[must_use]
    pub fn is_sealable(&self) -> bool {
        self.peer_bls_pub.is_some() && self.sealing.is_some()
    }

    // ---- Typed RPC methods ---------------------------------------------------------------------

    /// `dig.health` — liveness + capability summary. Public-read (unsealed).
    ///
    /// # Errors
    /// [`DigPeerError`] on transport/protocol failure or a peer RPC error.
    pub async fn health(&mut self) -> Result<Health> {
        self.call_public(Method::Health, &serde_json::Value::Null)
            .await
    }

    /// `dig.methods` — the method names this peer implements (agent self-describe). Public-read.
    ///
    /// # Errors
    /// [`DigPeerError`] on transport/protocol failure or a peer RPC error.
    pub async fn methods(&mut self) -> Result<Methods> {
        self.call_public(Method::Methods, &serde_json::Value::Null)
            .await
    }

    /// `dig.getNetworkInfo` — this peer's own network posture. **Directed** (sealed §5.4).
    ///
    /// # Errors
    /// [`DigPeerError::PeerNotSealable`]/[`DigPeerError::NoSealingIdentity`] if sealing is impossible;
    /// otherwise transport/protocol/seal failures or a peer RPC error.
    pub async fn get_network_info(&mut self) -> Result<NetworkInfo> {
        self.call_directed(Method::GetNetworkInfo, &serde_json::Value::Null)
            .await
    }

    /// `dig.getPeers` — the peers this peer knows (peer exchange). **Directed** (sealed §5.4).
    ///
    /// # Errors
    /// As [`Self::get_network_info`].
    pub async fn get_peers(&mut self) -> Result<PeersList> {
        self.call_directed(Method::GetPeers, &serde_json::Value::Null)
            .await
    }

    /// `dig.announce` — announce this node's presence to the peer. **Directed** (sealed §5.4).
    ///
    /// # Errors
    /// As [`Self::get_network_info`].
    pub async fn announce(&mut self, params: &AnnounceParams) -> Result<AnnounceAck> {
        self.call_directed(Method::Announce, params).await
    }

    /// `dig.getAvailability` — batch presence pre-check across stores/roots/capsules. Public content
    /// presence (unsealed §5.4 exemption); delegates to the dig-nat mux availability primitive.
    ///
    /// # Errors
    /// [`DigPeerError::Io`] on stream failure; [`DigPeerError::InvalidState`] after disconnect.
    pub async fn get_availability(
        &mut self,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse> {
        self.ensure_usable()?;
        Ok(self.conn.query_availability(items).await?)
    }

    /// `dig.fetchRange` — open a byte-range stream for `req` (public merkle-verified content, unsealed
    /// §5.4 exemption); delegates to the dig-nat mux range primitive. Returns the raw stream the
    /// caller reads [`dig_nat::RangeFrame`]s from.
    ///
    /// # Errors
    /// [`DigPeerError::Io`] on stream failure; [`DigPeerError::InvalidState`] after disconnect.
    pub async fn fetch_range(&mut self, req: &RangeRequest) -> Result<dig_nat::PeerStream> {
        self.ensure_usable()?;
        Ok(self.conn.open_range_stream(req).await?)
    }

    /// Cleanly tear down the connection. Once closed, RPCs fail with [`DigPeerError::InvalidState`].
    /// Dropping the underlying session ends the mux driver and closes the mTLS byte stream.
    pub async fn disconnect(mut self) {
        self.state = PeerState::Closed;
        // Dropping `self` (and thus `conn`/its `PeerSession`) closes the mux command channel, which
        // ends the driver task and tears down the underlying byte stream. The explicit state flip is
        // for symmetry + any post-teardown hooks; the drop does the real work.
    }

    // ---- Internal call plumbing ----------------------------------------------------------------

    /// Issue an UNSEALED (public-read) JSON-RPC call over a fresh stream.
    async fn call_public<P, R>(&mut self, method: Method, params: &P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        self.ensure_usable()?;
        let request = self.build_request(method, params)?;
        let body = rpc::to_json(&request)?;

        let mut stream = self.conn.open_stream().await?;
        rpc::write_framed(&mut stream, &body).await?;
        let response_bytes = rpc::read_framed(&mut stream).await?;
        Self::decode_result(&response_bytes)
    }

    /// Issue a DIRECTED (sealed §5.4) JSON-RPC call over a fresh stream — fail-closed if the peer is
    /// unbound or no sealing identity is configured.
    async fn call_directed<P, R>(&mut self, method: Method, params: &P) -> Result<R>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        self.ensure_usable()?;
        let peer_bls_pub = self.peer_bls_pub.ok_or(DigPeerError::PeerNotSealable)?;
        if self.sealing.is_none() {
            return Err(DigPeerError::NoSealingIdentity);
        }

        let request = self.build_request(method, params)?;
        let plaintext = rpc::to_json(&request)?;

        let (local_peer_id, peer_id) = (self.local_peer_id, self.peer_id);
        let sealing = self.sealing.as_mut().expect("checked is_some above");
        let (sealed_request, correlation) =
            sealing.seal_request(local_peer_id, peer_id, &peer_bls_pub, &plaintext)?;

        let mut stream = self.conn.open_stream().await?;
        rpc::write_framed(&mut stream, &sealed_request).await?;
        let sealed_response = rpc::read_framed(&mut stream).await?;

        let sealing = self.sealing.as_mut().expect("checked is_some above");
        let plaintext_response =
            sealing.open_response(&peer_bls_pub, correlation, &sealed_response)?;
        Self::decode_result(&plaintext_response)
    }

    /// Build a typed JSON-RPC request envelope with the next correlation id.
    fn build_request<P: Serialize>(
        &mut self,
        method: Method,
        params: &P,
    ) -> Result<JsonRpcRequest<serde_json::Value>> {
        let params_value =
            serde_json::to_value(params).map_err(|e| DigPeerError::Codec(e.to_string()))?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        Ok(JsonRpcRequest {
            jsonrpc: dig_rpc_protocol::Version,
            id: RequestId::Num(id),
            method: method.name().to_string(),
            params: Some(params_value),
        })
    }

    /// Decode a JSON-RPC response body into `R`, mapping a peer error envelope to
    /// [`DigPeerError::Rpc`].
    fn decode_result<R: DeserializeOwned>(bytes: &[u8]) -> Result<R> {
        let response: JsonRpcResponse<serde_json::Value> = rpc::from_json(bytes)?;
        if let Some(error) = response.as_error() {
            return Err(DigPeerError::Rpc(Box::new(error.clone())));
        }
        match response.as_result() {
            Some(value) => serde_json::from_value(value.clone())
                .map_err(|e| DigPeerError::Codec(e.to_string())),
            None => Err(DigPeerError::Codec(
                "response carried neither result nor error".into(),
            )),
        }
    }

    /// Reject an operation if the connection is not usable (post-disconnect).
    fn ensure_usable(&self) -> Result<()> {
        if self.state.is_usable() {
            Ok(())
        } else {
            Err(DigPeerError::InvalidState(self.state))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_rpc_protocol::error::{ErrorCode, ErrorOrigin, RpcError};

    /// **Proves:** a JSON-RPC success body decodes into the typed result.
    #[test]
    fn decode_result_returns_the_typed_result() {
        let response = JsonRpcResponse::success(RequestId::Num(1), serde_json::json!({"n": 7}));
        let bytes = serde_json::to_vec(&response).unwrap();
        let value: serde_json::Value = DigPeer::decode_result(&bytes).expect("decodes");
        assert_eq!(value["n"], 7);
    }

    /// **Proves:** a JSON-RPC error body maps to [`DigPeerError::Rpc`] carrying the peer's error.
    #[test]
    fn decode_result_maps_a_peer_error_envelope() {
        let rpc_error = RpcError::new(
            ErrorCode::MethodNotFound,
            "method not found",
            ErrorOrigin::Node,
        );
        let response: JsonRpcResponse = JsonRpcResponse::error(RequestId::Num(1), rpc_error);
        let bytes = serde_json::to_vec(&response).unwrap();
        let result: Result<serde_json::Value> = DigPeer::decode_result(&bytes);
        assert!(matches!(result, Err(DigPeerError::Rpc(_))));
    }

    /// **Proves:** a body that is neither result nor error is a `Codec` failure, not a silent success.
    #[test]
    fn decode_result_rejects_a_bodyless_response() {
        let result: Result<serde_json::Value> = DigPeer::decode_result(b"garbage");
        assert!(matches!(result, Err(DigPeerError::Codec(_))));
    }
}
