#![no_main]
//! Fuzz the length-prefix framing the daemon reads every request through.
//!
//! The input is fed to `FramedStream::recv` as a byte stream, and each result
//! is checked against an independent reading of the wire format
//! (`[len: u32 LE][body: len bytes]`, bodies above `MAX_MESSAGE_BYTES`
//! refused): a body of exactly `len` bytes, `MessageTooLarge(len)`, or an
//! unexpected-EOF error for a short header or body. Frames are read until the
//! first error, so back-to-back frames and trailing bytes are covered too.

use libfuzzer_sys::fuzz_target;
use sysknife_daemon::transport::framing::{FramedStream, FramingError};
use sysknife_types::MAX_MESSAGE_BYTES;
use tokio::io::{duplex, AsyncWriteExt};
use tokio::runtime::{Builder, Runtime};

thread_local! {
    static RUNTIME: Runtime = Builder::new_current_thread()
        .build()
        .expect("current-thread tokio runtime");
}

enum Expected<'a> {
    Body(&'a [u8]),
    TooLarge(usize),
    UnexpectedEof,
}

/// What the wire format says the next frame in `stream` is.
fn expected(stream: &[u8]) -> Expected<'_> {
    let Some((header, rest)) = stream.split_first_chunk::<4>() else {
        return Expected::UnexpectedEof;
    };
    let len = u32::from_le_bytes(*header) as usize;
    if len > MAX_MESSAGE_BYTES {
        Expected::TooLarge(len)
    } else if rest.len() < len {
        Expected::UnexpectedEof
    } else {
        Expected::Body(&rest[..len])
    }
}

fuzz_target!(|data: &[u8]| {
    RUNTIME.with(|runtime| {
        runtime.block_on(async {
            // The pipe buffers the whole input, so writing never waits on the reader.
            let (mut tx, rx) = duplex(data.len().max(1));
            tx.write_all(data).await.expect("buffered write");
            drop(tx);
            let mut framed = FramedStream::new(rx);

            let mut rest = data;
            loop {
                let want = expected(rest);
                let got = framed.recv().await;
                match (want, got) {
                    (Expected::Body(body), Ok(read)) => {
                        assert_eq!(read, body, "recv returned a different body");
                        rest = &rest[4 + body.len()..];
                    }
                    (Expected::TooLarge(len), Err(FramingError::MessageTooLarge(n))) => {
                        assert_eq!(n, len, "MessageTooLarge reported the wrong length");
                        return;
                    }
                    (Expected::UnexpectedEof, Err(FramingError::Io(e))) => {
                        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
                        return;
                    }
                    (_, got) => panic!("recv disagrees with the wire format: got {got:?}"),
                }
            }
        })
    });
});
