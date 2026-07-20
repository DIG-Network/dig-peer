//! The §5.4 end-to-end seal applied to **directed** RPC — layered ON TOP of mTLS.
//!
//! mTLS authenticates and encrypts the pipe, but any intermediary that terminates TLS (a relay, a
//! hole-punch forwarder) sees the plaintext of what it forwards. For a **directed** RPC — a request
//! carrying content specific to the recipient peer — that is not enough (CLAUDE.md §5.4 / #1075). So
//! dig-peer seals the request payload to the peer's verified BLS-G1 identity via [`dig_message`], so
//! only the receiving key can open it; the relay forwards ciphertext it cannot read.
//!
//! ## Identity model (node-to-node)
//!
//! A DIG node's sealing identity is its BLS-G1 machine identity — the same key that signed its mTLS
//! cert's #1204 binding (so a peer's `peer_bls_pub`, captured at the handshake, is exactly the key to
//! seal to). dig-message's DID fields carry routing identity; for node-to-node RPC we use each peer's
//! `peer_id` (`SHA-256(SPKI DER)`, 32 bytes) as the `Bytes32` identity id, and the receiver resolves
//! the sender's BLS key from the binding it captured for that same connection. No DID registry is
//! required: both ends captured each other's cert-bound BLS key at the mTLS handshake.
//!
//! ## Fail-closed
//!
//! If the peer presented no verified BLS-G1 key, or no local sealing identity is configured, a
//! directed call is REFUSED (never downgraded to an unsealed send). A response that fails
//! authenticated-open, signature, replay, or correlation checks is discarded, never surfaced.

use chia_protocol::Bytes32;
use chia_traits::Streamable as _;
use dig_message::{
    envelope::InteractionShape, open_message, seal_message, DigMessageEnvelope, ReplayGuard,
    SealParams,
};
use dig_tls::bls::{public_key_bytes, SecretKey};
use dig_tls::PeerId;

use crate::error::{DigPeerError, Result};

/// The dig-message type id dig-peer stamps on a sealed RPC envelope. A dedicated id keeps peer-RPC
/// traffic distinguishable from other directed message types (chat/email) in the shared registry.
///
/// Additive-only (SPEC §5.1 of dig-message): once assigned, never renumbered.
pub const RPC_MESSAGE_TYPE: u32 = 0x0000_5250; // "RP"

/// The local identity dig-peer uses to seal directed RPCs and open sealed responses.
///
/// It holds this node's BLS-G1 identity secret key (the machine identity that signed its mTLS cert
/// binding) and the key epoch. The DID fields for the seal are derived from the connection's
/// `peer_id`s, so this type is just the secret material plus the receive-side replay guard.
pub struct SealingIdentity {
    /// This node's BLS-G1 identity secret key (the ONE key that signs G2 and does the static G1 DH).
    secret_key: SecretKey,
    /// The key epoch, for rotation disambiguation.
    epoch: u32,
    /// The anti-replay guard for opening sealed responses on this connection.
    replay_guard: ReplayGuard,
    /// The strictly-monotonic per-connection send counter (§5.6 anti-replay).
    counter: u64,
}

impl std::fmt::Debug for SealingIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealingIdentity")
            .field("epoch", &self.epoch)
            .field("counter", &self.counter)
            .field("secret_key", &"<redacted BLS sk>")
            .finish()
    }
}

impl SealingIdentity {
    /// Create a sealing identity from this node's BLS-G1 identity secret key and key epoch.
    ///
    /// The secret key MUST be the same identity key that signed this node's mTLS cert binding, so
    /// that the peer resolves this node's sender key from the binding it captured at the handshake.
    #[must_use]
    pub fn new(secret_key: SecretKey, epoch: u32) -> Self {
        Self {
            secret_key,
            epoch,
            replay_guard: ReplayGuard::default(),
            counter: 0,
        }
    }

    /// This identity's BLS-G1 public key (48-byte compressed) — the value a peer must capture from
    /// this node's cert binding to open messages this identity seals.
    #[must_use]
    pub fn public_key(&self) -> [u8; 48] {
        public_key_bytes(&self.secret_key)
    }

    /// Seal `payload` as a directed request to `recipient` (their BLS-G1 key), authored by `sender`.
    ///
    /// Returns the byte-serialized sealed [`DigMessageEnvelope`] to write on the wire, plus the
    /// `correlation_id` the caller matches the response against. Advances the send counter.
    ///
    /// # Errors
    /// [`DigPeerError::Seal`] if the recipient key fails the subgroup check or the AEAD/compression
    /// step fails.
    pub fn seal_request(
        &mut self,
        sender: PeerId,
        recipient: PeerId,
        recipient_pub: &[u8; 48],
        payload: &[u8],
    ) -> Result<(Vec<u8>, Bytes32)> {
        self.counter = self.counter.wrapping_add(1);
        let correlation_id = correlation_from(sender, recipient, self.counter);
        let now_ms = now_ms();
        let params = SealParams {
            sender_sk: &self.secret_key,
            sender: peer_id_to_bytes32(sender),
            sender_epoch: self.epoch,
            recipient: peer_id_to_bytes32(recipient),
            recipient_pub,
            message_type: RPC_MESSAGE_TYPE,
            shape: InteractionShape::Request,
            correlation_id,
            stream: None,
            counter: self.counter,
            timestamp_ms: now_ms,
            expires_at: 0,
            payload,
        };
        let envelope = seal_message(&params).map_err(|e| DigPeerError::Seal(e.to_string()))?;
        let bytes = envelope
            .to_bytes()
            .map_err(|e| DigPeerError::Seal(e.to_string()))?;
        Ok((bytes, correlation_id))
    }

    /// Open a sealed response, verifying it was authored by `sender` (their captured BLS-G1 key),
    /// sealed to this identity, and correlates with `expected_correlation`.
    ///
    /// # Errors
    /// [`DigPeerError::Seal`] if authenticated-open / signature / replay / freshness verification
    /// fails; [`DigPeerError::Misdelivered`] if the response's `correlation_id` does not match.
    pub fn open_response(
        &mut self,
        sender_pub: &[u8; 48],
        expected_correlation: Bytes32,
        bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let envelope =
            DigMessageEnvelope::from_bytes(bytes).map_err(|e| DigPeerError::Seal(e.to_string()))?;
        let resolver = |_did: Bytes32, _epoch: u32| -> Option<[u8; 48]> { Some(*sender_pub) };
        let opened = open_message(
            &self.secret_key,
            &envelope,
            resolver,
            &mut self.replay_guard,
            now_ms(),
        )
        .map_err(|e| DigPeerError::Seal(e.to_string()))?;
        if opened.correlation_id != expected_correlation {
            return Err(DigPeerError::Misdelivered);
        }
        Ok(opened.payload)
    }
}

/// Convert a transport `peer_id` (`SHA-256(SPKI DER)`, 32 bytes) into the dig-message `Bytes32`
/// identity id used for the seal's DID fields.
fn peer_id_to_bytes32(peer_id: PeerId) -> Bytes32 {
    Bytes32::new(*peer_id.as_bytes())
}

/// Derive a deterministic-but-unique correlation id for a request from the directed pair and the
/// send counter. It need not be secret (it is a cleartext routing/multiplex field) — only unique per
/// in-flight request on this connection so the matching response is unambiguous.
fn correlation_from(sender: PeerId, recipient: PeerId, counter: u64) -> Bytes32 {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&counter.to_be_bytes());
    // Fold both peer_ids in so a correlation id is unique to this directed pair, not just the counter.
    for (i, b) in sender.as_bytes().iter().enumerate() {
        bytes[8 + (i % 24)] ^= *b;
    }
    for (i, b) in recipient.as_bytes().iter().enumerate() {
        bytes[8 + (i % 24)] ^= b.rotate_left(3);
    }
    Bytes32::new(bytes)
}

/// The receiver's wall clock in Unix milliseconds — the freshness/expiry basis dig-message enforces.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic BLS secret key from a label — test-only, never a production key path.
    fn sk(label: &str) -> SecretKey {
        let mut seed = [0u8; 32];
        let bytes = label.as_bytes();
        seed[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        SecretKey::from_seed(&seed)
    }

    fn pid(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    /// **Proves:** a sealed directed request is genuine ciphertext — the plaintext method name never
    /// appears in the on-wire bytes — and the intended recipient recovers it exactly.
    /// **Catches:** a regression that sends a directed payload in the clear (defeating §5.4).
    #[test]
    fn sealed_request_is_ciphertext_and_round_trips_to_the_intended_recipient() {
        let sender_sk = sk("seal/sender");
        let recipient_sk = sk("seal/recipient");
        let recipient_pub = public_key_bytes(&recipient_sk);
        let sender_pub = public_key_bytes(&sender_sk);

        let mut sender = SealingIdentity::new(sender_sk, 0);
        let plaintext = br#"{"jsonrpc":"2.0","id":1,"method":"dig.getPeers"}"#;
        let (wire, correlation) = sender
            .seal_request(pid(0xAA), pid(0xBB), &recipient_pub, plaintext)
            .expect("seal succeeds");

        // The sensitive method name is NOT present in the on-wire bytes.
        assert!(
            !contains_subslice(&wire, b"dig.getPeers"),
            "the plaintext method name leaked into the sealed on-wire bytes"
        );

        // The recipient opens it and recovers the exact plaintext (as if it were the response path).
        let mut recipient = SealingIdentity::new(recipient_sk, 0);
        let recovered = recipient
            .open_response(&sender_pub, correlation, &wire)
            .expect("recipient opens the sealed message");
        assert_eq!(recovered, plaintext);
    }

    /// **Proves:** a directed message sealed to peer X cannot be opened by a different peer Y — the
    /// seal binds confidentiality to the recipient's key, not merely to the mTLS pipe.
    /// **Catches:** a mis-targeted seal (wrong recipient key) that would let the wrong node read it.
    #[test]
    fn message_sealed_to_one_peer_cannot_be_opened_by_another() {
        let sender_sk = sk("wrong/sender");
        let sender_pub = public_key_bytes(&sender_sk);
        let intended_pub = public_key_bytes(&sk("wrong/intended"));
        let wrong_sk = sk("wrong/eavesdropper");

        let mut sender = SealingIdentity::new(sender_sk, 0);
        let (wire, correlation) = sender
            .seal_request(pid(1), pid(2), &intended_pub, b"secret-directed-payload")
            .expect("seal succeeds");

        let mut wrong = SealingIdentity::new(wrong_sk, 0);
        let opened = wrong.open_response(&sender_pub, correlation, &wire);
        assert!(
            matches!(opened, Err(DigPeerError::Seal(_))),
            "a peer the message was NOT sealed to must fail to open it, got {opened:?}"
        );
    }

    /// **Proves:** a response whose correlation id does not match the request is rejected as a
    /// misdelivery rather than surfaced to the caller.
    /// **Catches:** a client that accepts a response correlated to a different in-flight request.
    #[test]
    fn mismatched_correlation_is_rejected_as_misdelivery() {
        let sender_sk = sk("corr/sender");
        let sender_pub = public_key_bytes(&sender_sk);
        let recipient_sk = sk("corr/recipient");
        let recipient_pub = public_key_bytes(&recipient_sk);

        let mut sender = SealingIdentity::new(sender_sk, 0);
        let (wire, _correlation) = sender
            .seal_request(pid(3), pid(4), &recipient_pub, b"payload")
            .expect("seal succeeds");

        let mut recipient = SealingIdentity::new(recipient_sk, 0);
        let wrong_correlation = Bytes32::new([0x77; 32]);
        let opened = recipient.open_response(&sender_pub, wrong_correlation, &wire);
        assert!(
            matches!(opened, Err(DigPeerError::Misdelivered)),
            "a mismatched correlation must be a Misdelivery, got {opened:?}"
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
