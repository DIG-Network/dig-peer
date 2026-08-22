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

    // ---------------------------------------------------------------------------------------
    // GOLDEN WIRE VECTORS
    //
    // These pin the exact bytes dig-peer puts on the wire and the exact BLS-G1 key it derives from
    // a fixed seed. They exist so a chia-crate uplift (chia-bls / chia-protocol / chia-traits) can
    // be PROVEN byte-compatible with peers already deployed on the previous line, rather than
    // assumed. Blessed on the chia-0.26 line; they MUST NOT change when the line moves.
    //
    // A changed byte here is a compatibility break with deployed peers, not a migration detail.
    // ---------------------------------------------------------------------------------------

    /// Two NON-UNIFORM, NON-CANCELLING peer ids for the vectors.
    ///
    /// A uniform pair is blind here: `correlation_from` XORs `sender[i]` against
    /// `recipient[i].rotate_left(3)`, and e.g. `0x11 ^ 0x22.rotate_left(3) == 0` collapses the whole
    /// digest to zeros — a fixture that cannot show a derivation change. These vary per byte and
    /// exercise the `i % 24` fold, where bytes 8..=15 receive two contributions and 16..=31 one.
    fn vector_sender() -> PeerId {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(7).wrapping_add(0x13);
        }
        PeerId::from_bytes(b)
    }

    fn vector_recipient() -> PeerId {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(11).wrapping_add(0xa7);
        }
        PeerId::from_bytes(b)
    }

    /// The one fixed seed every vector below derives from. Never a production key path.
    const VECTOR_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// **Proves:** `SecretKey::from_seed` -> compressed BLS-G1 public key is byte-identical to the
    /// value the chia-0.26 line produced. This is the cryptographic anchor of the peer identity the
    /// mTLS binding commits to, so a change here silently re-identifies every node.
    /// **Catches:** a chia-bls uplift that alters EIP-2333 key derivation or G1 compression.
    #[test]
    fn vector_bls_g1_public_key_from_fixed_seed() {
        let pk = public_key_bytes(&SecretKey::from_seed(&VECTOR_SEED));
        assert_eq!(hex(&pk), "8f336467f057b373bb3c43815a10ec131119d1bf50c14fa3f9ad86c0ec074f920f936a5315a8365a37fee0afa34c32c6", "BLS-G1 derivation drifted");
    }

    /// **Proves:** the cleartext `correlation_id` routing field is derived byte-identically. Peers
    /// match responses to requests on this value, so drift misroutes every in-flight RPC.
    /// **Catches:** a `Bytes32` construction or byte-order change across the uplift.
    #[test]
    fn vector_correlation_id_for_a_fixed_directed_pair() {
        let mut id = SealingIdentity::new(SecretKey::from_seed(&VECTOR_SEED), 7);
        let recipient_pub = public_key_bytes(&SecretKey::from_seed(&[0x5au8; 32]));
        let (_wire, correlation) = id
            .seal_request(
                vector_sender(),
                vector_recipient(),
                &recipient_pub,
                b"vector-payload",
            )
            .expect("seal succeeds");
        assert_eq!(
            hex(correlation.as_ref()),
            "0000000000000001e8982b38b82918e8b402f1613edf7f1e3999fa5b83d26191",
            "correlation id derivation drifted"
        );
    }

    /// **Proves:** the sealed envelope's Chia-Streamable HEADER — version, message type, flags,
    /// correlation id, sender/recipient `Bytes32` DIDs, key epoch — serializes to the exact bytes a
    /// deployed peer expects. The sealed body carries an ephemeral KEM share and a timestamp and is
    /// therefore not byte-stable; the header is, and it is the part a peer parses to route.
    /// **Catches:** a `chia-traits` Streamable encoding change (field order, integer width,
    /// `Option` tagging) that would make a 0.36-built peer unreadable to a 0.26-built one.
    #[test]
    fn vector_sealed_envelope_header_bytes() {
        let mut id = SealingIdentity::new(SecretKey::from_seed(&VECTOR_SEED), 7);
        let recipient_pub = public_key_bytes(&SecretKey::from_seed(&[0x5au8; 32]));
        let (wire, _correlation) = id
            .seal_request(
                vector_sender(),
                vector_recipient(),
                &recipient_pub,
                b"vector-payload",
            )
            .expect("seal succeeds");
        let envelope = DigMessageEnvelope::from_bytes(&wire).expect("envelope parses");
        let header = envelope.header_bytes().expect("header serializes");
        assert_eq!(hex(&header), "0100005250050000000000000001e8982b38b82918e8b402f1613edf7f1e3999fa5b83d26191131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5eca7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99a4afbac5d0dbe6f1fc0000000700", "envelope header encoding drifted");
    }

    /// **Proves:** the transport `peer_id` -> `Bytes32` DID mapping is the identity mapping and its
    /// Streamable encoding is the raw 32 bytes, unprefixed and unreordered.
    /// **Catches:** a `chia-protocol` `Bytes32` representation change that would rewrite every DID
    /// field on the wire.
    #[test]
    fn vector_peer_id_to_bytes32_streamable_encoding() {
        let mut id = SealingIdentity::new(SecretKey::from_seed(&VECTOR_SEED), 7);
        let recipient_pub = public_key_bytes(&SecretKey::from_seed(&[0x5au8; 32]));
        let (wire, _c) = id
            .seal_request(
                vector_sender(),
                vector_recipient(),
                &recipient_pub,
                b"vector-payload",
            )
            .expect("seal succeeds");
        let envelope = DigMessageEnvelope::from_bytes(&wire).expect("envelope parses");
        assert_eq!(
            hex(&chia_traits::Streamable::to_bytes(&envelope.sender).unwrap()),
            "131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ec"
        );
        assert_eq!(
            hex(&chia_traits::Streamable::to_bytes(&envelope.recipient).unwrap()),
            "a7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99a4afbac5d0dbe6f1fc"
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
