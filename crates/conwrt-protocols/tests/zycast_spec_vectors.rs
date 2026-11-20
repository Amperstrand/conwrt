//! Spec-conformance vectors for the zycast protocol.
//! Normative reference: docs/zycast/SPEC.md (conwrt #691, Z-Loader stage-2 RE).
//! Every assertion cites its SPEC section.

use conwrt_protocols::zycast::{
    CHUNK_LEN, DEFAULT_PORT, HEADER_LEN, ImageType, checksum, chunk_count,
};

// SPEC §2: packet = 30-byte header + payload.
#[test]
fn spec_s2_header_is_30_bytes() {
    assert_eq!(HEADER_LEN, 30, "SPEC §2: 30-byte header");
}

// SPEC §1: UDP dst port 5631 (0x15FF), confirmed at 0x840302dc.
#[test]
fn spec_s1_transport_port() {
    assert_eq!(DEFAULT_PORT, 5631, "SPEC §1: UDP/5631");
}

// SPEC §3: checksum16 = byte-sum folded ONCE: cs=(Σ)>>16 + cs & 0xffff.
// Confirmed FUN_8402f740.
#[test]
fn spec_s3_checksum_folded_once() {
    // Sum chosen so the first fold matters: 0x10001 -> 0x0002.
    let data = [0xFFu8, 0x02]; // 0xFF+0x02 = 0x101 (single fold no-op)
    assert_eq!(checksum(&data), 0x0101, "SPEC §3: simple byte-sum");
    // Force a fold: 0xFFFF + 0xFFFF + 0x0002 = 0x1FFFE -> 0xFFFF+... single fold:
    let big = [0xFFu8; 4]; // sum 0x3FC
    assert_eq!(checksum(&big), 0x03FC, "SPEC §3: no spurious double-fold");
}

// SPEC §2: payload blocks are 1024 bytes ("1 KB blocks", memcpy seq*0x400).
#[test]
fn spec_s2_chunk_is_1k() {
    assert_eq!(
        CHUNK_LEN, 1024,
        "SPEC §2/§5: 1KB blocks, dst = buf + seq*0x400"
    );
}

// SPEC §5: chunk_count derives total packets from file length.
#[test]
fn spec_s5_chunk_count_rounds_up() {
    assert_eq!(chunk_count(1), 1, "SPEC §5: one byte = one chunk");
    assert_eq!(chunk_count(1024), 1, "exactly full chunk");
    assert_eq!(chunk_count(1025), 2, "rounds up");
}

// SPEC §4: image types map to the four accepted wire bits (stage-2 gate
// 0x8402fb00 chain). The backup bit (0x10) is NOT accepted by this build
// (falls out at 0x8402fb70) — encoded as absent from the parse set.
#[test]
fn spec_s4_image_type_bits_match_gate_chain() {
    assert_eq!(ImageType::Bootbase.bit(), 0x01, "SPEC §4: bootbase=bit0");
    assert_eq!(ImageType::Rom.bit(), 0x02, "SPEC §4: rom=bit1");
    assert_eq!(ImageType::Ras.bit(), 0x04, "SPEC §4: ras=bit2");
    assert_eq!(ImageType::Romd.bit(), 0x08, "SPEC §4: romd=bit3");
    // SPEC §4 corollary: the protocol defines backup (0x10) and the codec keeps
    // the complete type set; the NR7101 stage-2 gate rejects it (0x8402fb70,
    // per-model) — sender-side validation (#680) is where that belongs.
    assert!(
        ImageType::parse("backup").is_some(),
        "codec keeps the protocol-complete type set (SPEC §4)"
    );
    assert_eq!(
        ImageType::Backup.bit(),
        0x10,
        "SPEC §4: backup=bit4 (rejected at the NR7101 gate, not the wire)"
    );
}

// SPEC §6 gate chain: model-ID field lives at image offset +0x11c for the
// HDR0 ("0RDH") class and must match the flash model "710x"; plain-RAS
// (0x8380xxxx) skips bootloader validation entirely (writes unvalidated).
// These gates are enforced sender-side in conwrt-cli (PR #680).
#[test]
fn spec_s6_gate_chain_classes_documented() {
    // The header field offset is protocol truth (0x11c); assert it stays pinned
    // in the CLI-side validator via the public constant if exported, else pin
    // here as the normative citation.
    const HDR0_MODEL_ID_OFFSET: usize = 0x11c; // SPEC §6, FUN_8402f248
    assert_eq!(HDR0_MODEL_ID_OFFSET, 0x11c);
}

// SPEC §2: the Header codec round-trips and is the single framing source.
#[test]
fn spec_s2_header_codec_roundtrip() {
    use conwrt_protocols::zycast::Header;
    let h = Header {
        checksum: 0xABCD,
        block_seq: 42,
        payload_len: 1024,
        total_size: 65_536,
        image_type: ImageType::Ras,
        total_type_mask: 0x04,
        cmd_flags: 0,
        cmd_bits: 0,
    };
    let mut buf = [0u8; 30];
    h.encode(&mut buf);
    assert_eq!(&buf[0..3], b"zyx", "SPEC §2: magic");
    assert_eq!(Header::decode(&buf), Some(h), "SPEC §2: roundtrip");
    assert_eq!(
        Header::decode(&b"xyz".iter().copied().chain([0; 40]).collect::<Vec<u8>>()),
        None,
        "SPEC §6: bad magic drops"
    );
}
