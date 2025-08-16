use std::{fs, path::Path};
use crate::types::*;

const BUNDLE_MAGIC: &[u8; 4] = b"XLB1";
const BUNDLE_VERSION: u8 = 1;
const MEMO_PREVIEW_MAX: usize = 64;

fn leb128_write(mut v: u64, out: &mut Vec<u8>) {
    while v > 0x7F {
        out.push(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push((v as u8) & 0x7F);
}

fn tlv_u8(tag: u8, val: u8, out: &mut Vec<u8>) {
    out.push(tag);
    leb128_write(1, out);
    out.push(val);
}

fn tlv_u64(tag: u8, val: u64, out: &mut Vec<u8>) {
    out.push(tag);
    leb128_write(8, out);
    out.extend_from_slice(&val.to_le_bytes());
}

fn tlv_bytes(tag: u8, bytes: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    leb128_write(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Build a minimal, untrusted preview memo for device UI.
/// Device will later re-parse the canonical TX stream and reject on any mismatch.
/// TLVs included:
///   0x01 TX_TYPE (u8)
///   0x02 FEE     (u64 LE)
///   0x03 NONCE   (u64 LE)
///   0x10 OUT_COUNT (varint-as-payload; no value bytes)
///   0x20 OUT_ITEM repeated:
///        asset(32) | dest_pk(32) | amount(u64 LE) | extra_len(varint) | preview_len(varint) | preview_bytes
pub fn build_preview_memo(
    skel: &TxSkeleton,
    transfers: &[TransferSketch],
) -> Vec<u8> {
    // For this POC we only emit Transfers (type = 1)
    let tx_type = 1u8;
    let mut memo = Vec::new();

    tlv_u8(0x01, tx_type, &mut memo);
    tlv_u64(0x02, skel.fee, &mut memo);
    tlv_u64(0x03, skel.nonce, &mut memo);

    let out_count = skel.data_transfers.len() as u64;
    memo.push(0x10);
    leb128_write(out_count, &mut memo); // OUT_COUNT payload = varint itself

    for (i, t) in skel.data_transfers.iter().enumerate() {
        let asset = t.asset;
        let dest = t.destination;
        let amount = transfers[i].amount;

        let extra = transfers[i]
            .extra_data
            .as_ref()
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let extra_full_len = extra.len() as u64;
        let preview_len = core::cmp::min(extra.len(), MEMO_PREVIEW_MAX);
        let extra_preview = &extra[..preview_len];

        // Compose OUT_ITEM value
        // layout: asset(32) + dest(32) + amount(8) + extra_len(varint) + preview_len(varint) + preview_bytes
        let mut val = Vec::with_capacity(32 + 32 + 8 + 10 + 10 + preview_len);
        val.extend_from_slice(&asset);
        val.extend_from_slice(&dest);
        val.extend_from_slice(&amount.to_le_bytes());
        leb128_write(extra_full_len, &mut val);
        leb128_write(preview_len as u64, &mut val);
        val.extend_from_slice(extra_preview);

        // OUT_ITEM TLV
        memo.push(0x20);
        leb128_write(val.len() as u64, &mut memo);
        memo.extend_from_slice(&val);
    }

    memo
}

pub fn write_bundle(
    path: &str, 
    memo: &[u8], 
    tx_bytes: &[u8],
    blinders: &[[u8; 32]],
) {
    // Bundle V1 = MAGIC(4) | VER(1) | memo_len(varint) | memo | 
    //             blinders_len(varint) | blinders | tx_bytes
    let mut out = Vec::new();
    
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(1); // Version 2 with blinders
    
    // Memo section
    leb128_write(memo.len() as u64, &mut out);
    out.extend_from_slice(memo);
    
    // Blinders section
    let blinders_data: Vec<u8> = blinders.iter().flat_map(|b| b.iter()).copied().collect();
    leb128_write(blinders_data.len() as u64, &mut out);
    out.extend_from_slice(&blinders_data);
    
    // TX bytes
    out.extend_from_slice(tx_bytes);
    
    if let Some(p) = Path::new(path).parent() {
        let _ = fs::create_dir_all(p);
    }
    fs::write(path, &out).expect("write bundle");
    println!("wrote {} (v1 with blinders)", path);
}