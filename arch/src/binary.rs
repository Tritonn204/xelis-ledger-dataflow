use std::{fs, path::Path};
use crate::types::*;

const BUNDLE_MAGIC: &[u8; 4] = b"XLB1";
const BUNDLE_VERSION: u8 = 1;
const MEMO_PREVIEW_MAX: usize = 64;

// Asset table constants
const NATIVE_ASSET_INDEX: u8 = 0;
const NATIVE_ASSET: [u8; 32] = [0u8; 32];

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

/// Build asset table and return mapping function
fn build_asset_table(transfers: &[TransferSketch]) -> (Vec<[u8; 32]>, impl Fn(&[u8; 32]) -> u8) {
    let mut asset_table = Vec::new();
    let mut asset_map = std::collections::HashMap::new();
    
    // Native asset always gets index 0 (not stored in table)
    asset_map.insert(NATIVE_ASSET, NATIVE_ASSET_INDEX);
    
    // Collect unique non-native assets
    for transfer in transfers {
        if transfer.asset != NATIVE_ASSET && !asset_map.contains_key(&transfer.asset) {
            let index = (asset_table.len() + 1) as u8; // +1 because 0 is reserved for native
            asset_table.push(transfer.asset);
            asset_map.insert(transfer.asset, index);
        }
    }
    
    // Return table and lookup closure
    (asset_table, move |asset: &[u8; 32]| -> u8 {
        *asset_map.get(asset).unwrap_or(&NATIVE_ASSET_INDEX)
    })
}

/// Build a minimal, untrusted preview memo for device UI with asset table optimization.
/// Device will later re-parse the canonical TX stream and reject on any mismatch.
/// TLVs included:
pub const TAG_TX_TYPE: u8 = 0x01;
pub const TAG_FEE: u8 = 0x02;
pub const TAG_NONCE: u8 = 0x03;
pub const TAG_ASSET_TABLE: u8 = 0x04;  // New: asset table
pub const TAG_OUT_COUNT: u8 = 0x10;
pub const TAG_OUT_ITEM: u8 = 0x20;
pub const TAG_BURN: u8 = 0x30;
///        asset_index(1) | dest_pk(32) | amount(u64 LE) | extra_len(varint) | preview_len(varint) | preview_bytes
pub fn build_preview_memo(skel: &TxSkeleton, payload: &TxGeneratorPayload) -> Vec<u8> {
    let mut memo = Vec::new();

    // Common header
    match payload {
        TxGeneratorPayload::Transfers(_) => tlv_u8(TAG_TX_TYPE, 1, &mut memo), // TX_TRANSFER
        TxGeneratorPayload::Burn { .. }  => tlv_u8(TAG_TX_TYPE, 0, &mut memo), // TX_BURN
    }
    tlv_u64(TAG_FEE,   skel.fee,   &mut memo);
    tlv_u64(TAG_NONCE, skel.nonce, &mut memo);

    match payload {
        // ───────────────────────── Transfers ─────────────────────────
        TxGeneratorPayload::Transfers(transfers) => {
            // Asset table
            let (asset_table, idx_of) = build_asset_table(transfers);
            if !asset_table.is_empty() {
                let mut table = Vec::new();
                leb128_write(asset_table.len() as u64, &mut table);
                for a in &asset_table { table.extend_from_slice(a); }
                memo.push(TAG_ASSET_TABLE);
                leb128_write(table.len() as u64, &mut memo);
                memo.extend_from_slice(&table);
            }

            // OUT_COUNT (special case: tag + varint only)
            let out_count = skel.data_transfers.len() as u64;
            memo.push(TAG_OUT_COUNT);
            leb128_write(out_count, &mut memo);

            // OUT_ITEMs with preview
            // NOTE: we assume `skel.data_transfers.len() == transfers.len()`
            for (i, t) in skel.data_transfers.iter().enumerate() {
                let asset_idx = idx_of(&t.asset);
                let dest = t.destination;
                let amount = transfers[i].amount;

                let extra = transfers[i].extra_data.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);
                let extra_len = extra.len() as u64;
                let pv_len = core::cmp::min(extra.len(), MEMO_PREVIEW_MAX) as u64;

                // value
                let mut val = Vec::with_capacity(1 + 32 + 8 + 10 + 10 + pv_len as usize);
                val.push(asset_idx);
                val.extend_from_slice(&dest);
                val.extend_from_slice(&amount.to_le_bytes());
                leb128_write(extra_len, &mut val);
                leb128_write(pv_len, &mut val);
                val.extend_from_slice(&extra[..(pv_len as usize)]);

                memo.push(TAG_OUT_ITEM);
                leb128_write(val.len() as u64, &mut memo);
                memo.extend_from_slice(&val);
            }
        }

        // ─────────────────────────── Burn ───────────────────────────
        TxGeneratorPayload::Burn { amount, asset } => {
            // Optional asset table for non-native
            let asset_idx = if *asset == NATIVE_ASSET {
                NATIVE_ASSET_INDEX
            } else {
                let mut table = Vec::new();
                leb128_write(1, &mut table);
                table.extend_from_slice(asset);
                memo.push(TAG_ASSET_TABLE);
                leb128_write(table.len() as u64, &mut memo);
                memo.extend_from_slice(&table);
                1u8
            };

            // TAG_BURN value: asset_idx(1) | amount(8) | preview_len(varint=0)
            let mut val = Vec::with_capacity(1 + 8 + 1);
            val.push(asset_idx);
            val.extend_from_slice(&amount.to_le_bytes());
            leb128_write(0, &mut val); // burns can't have extra → no preview

            memo.push(TAG_BURN);
            leb128_write(val.len() as u64, &mut memo);
            memo.extend_from_slice(&val);
        }
    }

    // println!("MEMO after build: {}", hex::encode(&memo));

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
    out.push(BUNDLE_VERSION);
    
    // Memo section
    leb128_write(memo.len() as u64, &mut out);
    out.extend_from_slice(memo);
    
    // println!("OUT after memo write: {}", hex::encode(&out));

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