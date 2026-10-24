//! Byte-accounting sweep for the POST pipeline (#226 verification
//! 2026-10-24): for every image size, the bytes that leave
//! [`RecoveryPost`] after the request head must equal
//! multipart-header + image + footer exactly, and match
//! `Multipart::content_len()` — the number `start()` declared in
//! `Content-Length`. A mismatch here desyncs the one-request server
//! (it waits for bytes that never come) — the failure mode is a silent
//! mutual hang, so it gets its own pinned sweep.
//!
//! (Forensics note: the 2026-10-24 "short body" scare was a QA-mock
//! bug — a header read that swallowed piggybacked body bytes. This
//! suite pins the ENGINE invariant so the next scare starts ruled
//! out. The HIL mock's byte-at-a-time `read_head` is immune by
//! construction.)

use conwrt_agent_proto::protocol::StreamChunk;
use conwrt_executor::multipart::{Multipart, UPLOAD_FIELD};
use conwrt_executor::transfer::TransferState;
use conwrt_executor::{HttpIo, RecoveryPost};

struct CountIo {
    written: Vec<u8>,
}

impl HttpIo for CountIo {
    type Error = ();
    async fn write_all(&mut self, data: &[u8]) -> Result<(), ()> {
        self.written.extend_from_slice(data);
        Ok(())
    }
    async fn read_response(&mut self, _out: &mut Vec<u8>) -> Result<(), ()> {
        Ok(())
    }
}

#[tokio::test]
async fn body_bytes_equal_content_len_across_sizes() {
    for size in [4096usize, 8192, 16384, 32768, 65536, 131072] {
        let image: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mp = Multipart {
            boundary: "----WebKitFormBoundarye3b0c44298fc1c14",
            field: UPLOAD_FIELD,
            filename: "recovery.bin",
            image_len: size as u64,
        };
        let expected_len = mp.content_len().expect("sane size");
        let header = mp.header();
        let footer = mp.footer();

        let mut xfer = TransferState::new(1, 8 * 1024);
        let mut io = CountIo {
            written: Vec::new(),
        };
        let mut post = RecoveryPost::new(mp, "192.168.0.1", "/upload");

        let mut sent = 0usize;
        while sent < size {
            let end = (sent + 4096).min(size);
            xfer.accept(&StreamChunk {
                transfer_id: 1,
                offset: sent as u64,
                total: Some(size as u64),
                data: image[sent..end].to_vec(),
            })
            .expect("accept");
            if !post.committed() {
                post.start(&mut io, &xfer).await.expect("start");
            }
            post.pump(&mut io, &mut xfer).await.expect("pump");
            sent = end;
        }
        let _ = post.finish(&mut io, &xfer).await;

        let split = io
            .written
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("head terminator")
            + 4;
        let body = &io.written[split..];
        assert_eq!(
            body.len(),
            expected_len as usize,
            "size {size}: body bytes != Content-Length"
        );
        assert!(body.starts_with(&header), "size {size}: multipart header");
        assert!(body.ends_with(&footer), "size {size}: multipart footer");
        assert_eq!(
            &body[header.len()..body.len() - footer.len()],
            &image[..],
            "size {size}: image bytes must be exact"
        );
        assert!(
            xfer.is_complete() && xfer.buffered() == 0,
            "size {size}: window drained"
        );
    }
}
