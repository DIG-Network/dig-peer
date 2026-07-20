//! The dig-peer error taxonomy.
//!
//! Every fallible entry point on [`DigPeer`](crate::DigPeer) returns [`DigPeerError`]. The variants
//! separate the four failure domains a peer client faces so a caller can react precisely:
//! *transport* (could not reach the peer), *protocol* (the peer answered, but the RPC failed),
//! *seal* (the §5.4 end-to-end encryption could not be applied or verified — always fail-closed),
//! and *state* (the operation is invalid for the connection's current lifecycle state).

use dig_nat::NatError;
use dig_rpc_protocol::RpcError;

/// The result type for every [`DigPeer`](crate::DigPeer) operation.
pub type Result<T> = std::result::Result<T, DigPeerError>;

/// A failure of a [`DigPeer`](crate::DigPeer) operation.
///
/// The variants are grouped by domain (transport / protocol / seal / state / codec) so a caller can
/// distinguish "could not reach the peer" from "the peer refused the request" from "the message could
/// not be sealed to the peer" — each of which warrants a different response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DigPeerError {
    /// The transport could not establish (or lost) the connection — every NAT-traversal tier failed,
    /// no tier was composable, or the mux/stream I/O broke. Wraps the underlying [`NatError`].
    #[error("peer transport failed: {0}")]
    Transport(#[from] NatError),

    /// Stream I/O failed while sending a request or receiving a response (the connection dropped
    /// mid-call, or a framed body exceeded the size bound).
    #[error("peer stream I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// The peer answered with a JSON-RPC error envelope. Carries the peer's canonical [`RpcError`]
    /// (code + message + origin) verbatim so the caller sees exactly what the peer reported. Boxed so
    /// the large error envelope does not bloat every [`Result`] on the hot path.
    #[error("peer returned an RPC error: {0:?}")]
    Rpc(Box<RpcError>),

    /// A directed (sealed) RPC was requested but the connection has NO verified peer BLS-G1 key
    /// (a legacy/unbound peer, or binding verification was off). Sealing is **fail-closed**: without
    /// a verified recipient key dig-peer refuses to send, rather than fall back to an unsealed send.
    #[error("cannot send a directed sealed RPC: the peer presented no verified BLS-G1 identity")]
    PeerNotSealable,

    /// A directed (sealed) RPC was requested but no local sealing identity was configured. Set one
    /// with [`DigPeer::with_sealing_identity`](crate::DigPeer::with_sealing_identity) before making
    /// directed calls.
    #[error("cannot seal a directed RPC: no local sealing identity configured")]
    NoSealingIdentity,

    /// The §5.4 seal or open failed — the payload could not be sealed to the peer, or a received
    /// response failed authenticated decryption / signature / replay verification. Fail-closed: the
    /// call errors rather than surfacing unverified bytes.
    #[error("message seal/open failed: {0}")]
    Seal(String),

    /// The peer delivered a sealed response that does not correlate with the request that was sent
    /// (wrong correlation id) — discarded rather than surfaced (a misdelivery cannot be trusted).
    #[error("sealed response did not correlate with the request")]
    Misdelivered,

    /// A response body could not be (de)serialized into the expected typed shape.
    #[error("could not (de)serialize an RPC payload: {0}")]
    Codec(String),

    /// The operation is invalid for the connection's current lifecycle state (e.g. an RPC after
    /// [`disconnect`](crate::DigPeer::disconnect)).
    #[error("operation invalid in state {0:?}")]
    InvalidState(crate::state::PeerState),
}
