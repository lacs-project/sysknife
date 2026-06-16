use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum body size accepted by `recv`. Connections sending a larger
/// length header are terminated immediately.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("message too large: {0} bytes (max {MAX_MESSAGE_BYTES})")]
    MessageTooLarge(usize),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Wraps an async stream with 4-byte little-endian length-prefix framing.
///
/// Each message is sent as `[len: u32 LE][body: len bytes]`. The maximum
/// body length is [`MAX_MESSAGE_BYTES`]; larger messages are rejected at
/// both the send and receive side.
pub struct FramedStream<S> {
    inner: S,
}

impl<S> FramedStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin> FramedStream<S> {
    pub async fn send(&mut self, data: &[u8]) -> Result<(), FramingError> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(FramingError::MessageTooLarge(data.len()));
        }
        self.inner
            .write_all(&(data.len() as u32).to_le_bytes())
            .await?;
        self.inner.write_all(data).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>, FramingError> {
        let mut header = [0u8; 4];
        self.inner.read_exact(&mut header).await?;
        let len = u32::from_le_bytes(header) as usize;
        if len > MAX_MESSAGE_BYTES {
            return Err(FramingError::MessageTooLarge(len));
        }
        let mut body = vec![0u8; len];
        self.inner.read_exact(&mut body).await?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Send `data` from one half of a duplex pair, receive from the other.
    async fn round_trip(data: &[u8]) -> Vec<u8> {
        let (a, b) = duplex(MAX_MESSAGE_BYTES + 8);
        let mut sender = FramedStream::new(a);
        let mut recvr = FramedStream::new(b);
        sender.send(data).await.expect("send failed");
        recvr.recv().await.expect("recv failed")
    }

    #[tokio::test]
    async fn round_trip_empty_message() {
        assert_eq!(round_trip(b"").await, b"");
    }

    #[tokio::test]
    async fn round_trip_single_byte() {
        assert_eq!(round_trip(b"x").await, b"x");
    }

    #[tokio::test]
    async fn round_trip_4095_bytes() {
        let data = vec![0xABu8; 4095];
        assert_eq!(round_trip(&data).await, data);
    }

    #[tokio::test]
    async fn round_trip_4096_bytes() {
        let data = vec![0xCDu8; 4096];
        assert_eq!(round_trip(&data).await, data);
    }

    #[tokio::test]
    async fn round_trip_json_payload() {
        let msg = br#"{"type":"preview","action_name":"GetSystemState"}"#;
        assert_eq!(round_trip(msg).await, msg);
    }

    #[tokio::test]
    async fn send_rejects_message_over_4mib() {
        let (a, _b) = duplex(8);
        let mut sender = FramedStream::new(a);
        let oversized = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let err = sender.send(&oversized).await.unwrap_err();
        assert!(
            matches!(err, FramingError::MessageTooLarge(n) if n == MAX_MESSAGE_BYTES + 1),
            "expected MessageTooLarge, got: {err}"
        );
    }

    #[tokio::test]
    async fn recv_rejects_header_claiming_over_4mib() {
        let (a, b) = duplex(16);
        let mut raw_sender = a;
        let mut recvr = FramedStream::new(b);
        // Write a header claiming MAX + 1 bytes
        let oversized_len = (MAX_MESSAGE_BYTES + 1) as u32;
        raw_sender
            .write_all(&oversized_len.to_le_bytes())
            .await
            .unwrap();
        let err = recvr.recv().await.unwrap_err();
        assert!(
            matches!(err, FramingError::MessageTooLarge(n) if n == MAX_MESSAGE_BYTES + 1),
            "expected MessageTooLarge, got: {err}"
        );
    }

    #[tokio::test]
    async fn multiple_messages_on_same_stream() {
        let (a, b) = duplex(MAX_MESSAGE_BYTES + 8);
        let mut sender = FramedStream::new(a);
        let mut recvr = FramedStream::new(b);
        sender.send(b"first").await.unwrap();
        sender.send(b"second").await.unwrap();
        assert_eq!(recvr.recv().await.unwrap(), b"first");
        assert_eq!(recvr.recv().await.unwrap(), b"second");
    }
}
