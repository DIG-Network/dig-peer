//! The peer-stream RPC framing — how a typed JSON-RPC call rides one mux stream.
//!
//! `dig-rpc` is an HTTP JSON-RPC *server*; the peer surface instead carries JSON-RPC over `dig-nat`'s
//! multiplexed mTLS streams. dig-peer defines that on-stream framing here and is the CLIENT that
//! speaks it. Each call opens ONE fresh logical stream, writes a single length-prefixed request body,
//! reads a single length-prefixed response body, and lets the stream close — a clean request/response
//! per stream, with concurrency provided by the mux (open many streams).
//!
//! ## Framing (normative)
//!
//! A body is a `u32` big-endian length prefix followed by that many bytes — the SAME uniform framing
//! `dig-nat`'s control messages use, so the two never disagree. For an **unsealed** (public-read)
//! call the body is the JSON of a `JsonRpcRequest`/`JsonRpcResponse`. For a **directed** (sealed)
//! call the body is the byte-serialized sealed [`dig_message`] envelope wrapping that JSON (§5.4).
//! The [`MAX_BODY`] bound guards against a malicious length prefix forcing a huge allocation.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{DigPeerError, Result};

/// Maximum length-prefixed body dig-peer will read — guards against a hostile length prefix. Matches
/// dig-nat's control-frame bound (64 KiB) for small control/RPC messages.
pub const MAX_BODY: usize = 64 * 1024;

/// Write a length-prefixed body (`u32` big-endian length + bytes) to `w`.
pub async fn write_framed<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<()> {
    if body.len() > MAX_BODY {
        return Err(DigPeerError::Codec(format!(
            "outbound body {} exceeds the {MAX_BODY}-byte bound",
            body.len()
        )));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed body (`u32` big-endian length + bytes) from `r`, bounded by [`MAX_BODY`].
pub async fn read_framed<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_BODY {
        return Err(DigPeerError::Codec(format!(
            "inbound body length {len} exceeds the {MAX_BODY}-byte bound"
        )));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Serialize a value to a JSON body for the wire.
pub fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| DigPeerError::Codec(e.to_string()))
}

/// Deserialize a JSON body from the wire into a typed value.
pub fn from_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| DigPeerError::Codec(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** a body written by [`write_framed`] is read back byte-identically by
    /// [`read_framed`] — the length-prefixed framing is self-consistent.
    #[tokio::test]
    async fn framed_body_round_trips() {
        let body = b"{\"jsonrpc\":\"2.0\"}".to_vec();
        let mut buf = Vec::new();
        write_framed(&mut buf, &body).await.expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        let read = read_framed(&mut cursor).await.expect("read");
        assert_eq!(read, body);
    }

    /// **Proves:** an empty body frames + unframes cleanly (a zero-length prefix is valid).
    #[tokio::test]
    async fn empty_body_round_trips() {
        let mut buf = Vec::new();
        write_framed(&mut buf, &[]).await.expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_framed(&mut cursor).await.expect("read").is_empty());
    }

    /// **Proves:** writing a body over the [`MAX_BODY`] bound is refused, guarding against a caller
    /// serializing an oversized payload.
    #[tokio::test]
    async fn oversized_write_is_refused() {
        let big = vec![0u8; MAX_BODY + 1];
        let mut buf = Vec::new();
        let result = write_framed(&mut buf, &big).await;
        assert!(matches!(result, Err(DigPeerError::Codec(_))));
    }

    /// **Proves:** a length prefix over [`MAX_BODY`] is rejected before allocating, guarding against a
    /// hostile prefix forcing a huge allocation.
    #[tokio::test]
    async fn oversized_length_prefix_is_rejected() {
        let mut framed = ((MAX_BODY + 1) as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&[0u8; 8]);
        let mut cursor = std::io::Cursor::new(framed);
        assert!(matches!(
            read_framed(&mut cursor).await,
            Err(DigPeerError::Codec(_))
        ));
    }

    /// **Proves:** [`to_json`]/[`from_json`] round-trip a value; a malformed body is a `Codec` error.
    #[test]
    fn json_round_trips_and_rejects_garbage() {
        let value = serde_json::json!({"a": 1});
        let bytes = to_json(&value).expect("to_json");
        let back: serde_json::Value = from_json(&bytes).expect("from_json");
        assert_eq!(value, back);
        assert!(matches!(
            from_json::<serde_json::Value>(b"not json"),
            Err(DigPeerError::Codec(_))
        ));
    }
}
