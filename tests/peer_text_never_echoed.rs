//! A peer's own bytes must never reach the text of a `DigPeerError` (#1674).
//!
//! `dig-peer` is the CLIENT side of the L7 peer RPC, so every byte it decodes came from a remote
//! node. `serde_json`'s error message quotes the offending input back, and `DigPeerError::Codec`
//! relayed that message verbatim — so a hostile or buggy peer chose text that appeared in the
//! caller's diagnostics.
//!
//! The tests drive `rpc::from_json`, the real public decode used by every response path, and assert
//! the precondition (that serde echoes) before asserting the fix.

use dig_peer::rpc;

/// Inert ASCII with nothing JSON-escapable, so it is byte-identical whether rendered raw or through
/// `{:?}`. A marker that needed escaping would let a pass mean merely "serde re-quoted it".
const STRANGER_MARKER: &str = "PEER-CHOSEN-TEXT-0f9a1c";

/// PRECONDITION — serde echoes, so the tests below test something.
#[test]
fn serde_json_quotes_the_peer_input_back_verbatim() {
    let body = format!(r#""{STRANGER_MARKER}""#);

    let raw = serde_json::from_slice::<u64>(body.as_bytes())
        .expect_err("a string is not a u64")
        .to_string();

    assert!(raw.contains(STRANGER_MARKER), "premise gone: {raw}");
}

/// THE PROPERTY — the real decode's error carries none of the peer's bytes, in either rendering.
#[test]
fn peer_bytes_never_reach_a_codec_error() {
    let body = format!(r#""{STRANGER_MARKER}""#);

    let err = rpc::from_json::<u64>(body.as_bytes()).expect_err("a string is not a u64");

    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains(STRANGER_MARKER),
            "the codec error echoed the peer's bytes: {rendered}"
        );
    }
}

/// THE CONTROL — the fix must not be "say less". Deleting the detail would satisfy the assertion
/// above perfectly, so the diagnosis is asserted separately.
#[test]
fn a_codec_error_still_diagnoses_the_failure() {
    let body = format!(r#""{STRANGER_MARKER}""#);

    let err = rpc::from_json::<u64>(body.as_bytes()).expect_err("a string is not a u64");

    let msg = err.to_string();
    assert!(
        msg.contains("line 1") && msg.contains("column"),
        "a developer must still be able to locate the failure: {msg}"
    );
    assert!(
        msg.contains("data"),
        "a developer must still be able to tell malformed JSON from a wrong shape: {msg}"
    );
}

/// The log-injection half: a control character a peer smuggled in must not become a line break.
#[test]
fn a_forged_log_line_cannot_be_smuggled_through_a_codec_error() {
    // Encoded with serde_json so the `\n` is a legal JSON escape that decodes to a REAL newline,
    // rather than a raw control byte that would fail as a SYNTAX error and never reach the echo.
    let body = serde_json::to_vec(&serde_json::json!(format!(
        "{STRANGER_MARKER}\n2026-07-31T00:00:00Z ERROR forged"
    )))
    .expect("the fixture serializes");

    let err = rpc::from_json::<u64>(&body).expect_err("a string is not a u64");

    let msg = err.to_string();
    assert!(
        !msg.contains('\n') && !msg.contains('\r'),
        "a peer forged a line break: {msg:?}"
    );
    assert!(!msg.contains("forged"), "the error echoed it: {msg:?}");
}
