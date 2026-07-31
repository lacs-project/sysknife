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
        // Grow the buffer as bytes actually arrive rather than pre-allocating the
        // full claimed length. A peer that announces a large body but withholds
        // it (partial-frame DoS, #150) then pins only what it has actually sent,
        // not the whole claim — so N stalled connections cannot hold
        // N * MAX_MESSAGE_BYTES of memory while their pre-auth deadline runs.
        // The initial reservation is bounded, and reads are chunked.
        let mut body = Vec::with_capacity(len.min(INITIAL_BODY_CAPACITY));
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        while body.len() < len {
            let want = (len - body.len()).min(chunk.len());
            let n = self.inner.read(&mut chunk[..want]).await?;
            if n == 0 {
                return Err(FramingError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before the full frame body arrived",
                )));
            }
            body.extend_from_slice(&chunk[..n]);
        }
        Ok(body)
    }
}

/// Upper bound on the buffer reserved up front for a frame body, regardless of
/// the claimed length. A larger body grows the buffer incrementally as data
/// arrives, so a withheld body never costs more than this.
const INITIAL_BODY_CAPACITY: usize = 64 * 1024;

/// Size of the stack read buffer used to stream a frame body.
const READ_CHUNK_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

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
    async fn a_body_arriving_in_many_small_chunks_is_reassembled() {
        // Payload larger than one read chunk, delivered through a small duplex
        // buffer so recv must loop over several reads and stitch them together.
        let payload = vec![0xABu8; 3 * READ_CHUNK_BYTES + 123];
        let (mut a, b) = duplex(4096);
        let mut recvr = FramedStream::new(b);
        let p2 = payload.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&(p2.len() as u32).to_le_bytes()).await.unwrap();
            a.write_all(&p2).await.unwrap();
        });
        let got = recvr.recv().await.expect("recv should reassemble the body");
        writer.await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn a_withheld_body_after_a_large_length_claim_errors_without_buffering_the_claim() {
        // Announce the maximum body size but send only a few bytes, then close.
        // The old code allocated the full 4 MiB up front (vec![0u8; len]); the
        // streaming reader must instead error out promptly on EOF (#150) — it
        // neither hangs waiting for the withheld body nor returns a short body
        // as if complete.
        let (mut a, b) = duplex(1024);
        let mut recvr = FramedStream::new(b);
        let writer = tokio::spawn(async move {
            a.write_all(&(MAX_MESSAGE_BYTES as u32).to_le_bytes())
                .await
                .unwrap();
            a.write_all(b"partial").await.unwrap();
            drop(a); // close -> EOF before the claimed body arrives
        });
        let err = recvr
            .recv()
            .await
            .expect_err("a truncated body must error, not hang or succeed");
        writer.await.unwrap();
        match err {
            FramingError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected UnexpectedEof, got {other}"),
        }
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
    async fn truncated_body_errors_instead_of_hanging() {
        // A header promising N bytes followed by fewer than N, then EOF. The
        // reader must fail, not block forever waiting for bytes that will
        // never arrive — a peer that dies mid-frame otherwise pins a
        // connection slot for the life of the daemon.
        let (a, b) = duplex(MAX_MESSAGE_BYTES + 8);
        let mut recvr = FramedStream::new(b);
        let mut raw_sender = a;

        raw_sender.write_all(&8u32.to_le_bytes()).await.unwrap();
        raw_sender.write_all(b"abc").await.unwrap(); // 3 of the promised 8
        drop(raw_sender); // EOF mid-body

        let err = recvr.recv().await.unwrap_err();
        assert!(
            matches!(err, FramingError::Io(_)),
            "a truncated body must surface as an I/O error, got: {err}"
        );
    }

    #[tokio::test]
    async fn truncated_header_errors_instead_of_hanging() {
        // Same failure mode one step earlier: the 4-byte length prefix itself
        // arrives incomplete.
        let (a, b) = duplex(MAX_MESSAGE_BYTES + 8);
        let mut recvr = FramedStream::new(b);
        let mut raw_sender = a;

        raw_sender.write_all(&[0x01, 0x02]).await.unwrap(); // 2 of 4
        drop(raw_sender);

        let err = recvr.recv().await.unwrap_err();
        assert!(
            matches!(err, FramingError::Io(_)),
            "a truncated header must surface as an I/O error, got: {err}"
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
