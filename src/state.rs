//! The [`DigPeer`](crate::DigPeer) connection lifecycle.
//!
//! A DigPeer moves through a small, explicit state machine so callers (and the crate itself) always
//! know whether an RPC may be issued. The transitions are deliberately minimal — dig-peer's job is to
//! be a thin, honest client, so the state is just enough to reject use-after-disconnect and to report
//! liveness, not a full reconnection engine (opportunistic re-dial is a documented follow-up).

/// The lifecycle state of a [`DigPeer`](crate::DigPeer) connection.
///
/// A freshly [`connect`](crate::DigPeer::connect)ed peer is [`Connected`](PeerState::Connected).
/// [`disconnect`](crate::DigPeer::disconnect) moves it to [`Closed`](PeerState::Closed) terminally;
/// any RPC attempted after that fails with [`DigPeerError::InvalidState`](crate::DigPeerError::InvalidState).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerState {
    /// The mTLS connection is established and RPCs may be issued.
    Connected,
    /// The connection was explicitly torn down; no further RPCs are possible. Terminal.
    Closed,
}

impl PeerState {
    /// Whether an RPC may be issued in this state.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, PeerState::Connected)
    }
}
