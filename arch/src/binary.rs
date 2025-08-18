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
///   0x01 TX_TYPE (u8)
///   0x02 FEE     (u64 LE)
///   0x03 NONCE   (u64 LE)
///   0x04 ASSET_TABLE: count(varint) | asset1(32) | asset2(32) | ...
///   0x10 OUT_COUNT (varint-as-payload; no value bytes)
///   0x20 OUT_ITEM repeated:
///        asset_index(1) | dest_pk(32) | amount(u64 LE) | extra_len(varint) | preview_len(varint) | preview_bytes
pub fn build_preview_memo(
    skel: &TxSkeleton,
    transfers: &[TransferSketch],
) -> Vec<u8> {
    // For this POC we only emit Transfers (type = 1)
    let tx_type = 1u8;
    let mut memo = Vec::new();

    // Build asset table
    let (asset_table, get_asset_index) = build_asset_table(transfers);
    
    // Write standard fields
    tlv_u8(0x01, tx_type, &mut memo);
    tlv_u64(0x02, skel.fee, &mut memo);
    tlv_u64(0x03, skel.nonce, &mut memo);

    // Write asset table if we have non-native assets
    if !asset_table.is_empty() {
        memo.push(0x04); // TAG_ASSET_TABLE
        
        // Calculate table size
        let mut table_data = Vec::new();
        leb128_write(asset_table.len() as u64, &mut table_data);
        for asset in &asset_table {
            table_data.extend_from_slice(asset);
        }
        
        // Write table TLV
        leb128_write(table_data.len() as u64, &mut memo);
        memo.extend_from_slice(&table_data);
        
        println!("Asset table: {} unique non-native assets", asset_table.len());
    }

    // Write output count
    let out_count = skel.data_transfers.len() as u64;
    memo.push(0x10);
    leb128_write(out_count, &mut memo); // OUT_COUNT payload = varint itself

    // Write outputs with asset indices
    for (i, t) in skel.data_transfers.iter().enumerate() {
        let asset_index = get_asset_index(&t.asset);
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

        // Compose OUT_ITEM value (now with asset_index instead of full asset)
        // layout: asset_index(1) + dest(32) + amount(8) + extra_len(varint) + preview_len(varint) + preview_bytes
        let mut val = Vec::with_capacity(1 + 32 + 8 + 10 + 10 + preview_len);
        val.push(asset_index);  // Just 1 byte instead of 32!
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

    // Log space savings
    let old_size = out_count as usize * 32; // Old: 32 bytes per asset
    let new_size = asset_table.len() * 32 + out_count as usize; // New: table + 1 byte per output
    println!("Memo asset data: {} → {} bytes (saved {} bytes)", 
        old_size, new_size, old_size.saturating_sub(new_size));

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