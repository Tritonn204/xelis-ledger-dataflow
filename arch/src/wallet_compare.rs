use crate::types::*;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Deserialize)]
struct WalletLikeTx {
    // Allow either top-level or nested `data.*` by using Option and flatten later.
    #[serde(default)]
    data: Option<WalletLikeData>,
    #[serde(default)]
    transfers: Option<Vec<WalletLikeTransfer>>,
    #[serde(default)]
    range_proof: Option<String>,
    #[serde(default)]
    fee: Option<u64>,
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    reference: Option<WalletLikeReference>,
}

#[derive(Debug, Deserialize)]
struct WalletLikeData {
    #[serde(default)]
    transfers: Option<Vec<WalletLikeTransfer>>,
    #[serde(default)]
    range_proof: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WalletLikeTransfer {
    // We only need fields required for comparison; add more later if useful.
    commitment: String, // hex
    #[allow(dead_code)]
    asset: Option<String>,
    #[allow(dead_code)]
    destination: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WalletLikeReference {
    hash: String, // hex
    topoheight: u64,
}

/// Hex decode into Vec<u8>
fn hex_to_vec(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_start_matches("0x");
    hex::decode(s).ok()
}

/// Convert 32-byte hex into [u8;32]
fn hex32(s: &str) -> Option<[u8;32]> {
    let v = hex_to_vec(s)?;
    if v.len() != 32 { return None; }
    let mut out = [0u8;32];
    out.copy_from_slice(&v);
    Some(out)
}

/// Extract transfers array from either {transfers:[..]} or {data:{transfers:[..]}}
fn extract_transfers(w: &WalletLikeTx) -> Option<&[WalletLikeTransfer]> {
    if let Some(ts) = &w.transfers {
        return Some(ts.as_slice());
    }
    if let Some(d) = &w.data {
        if let Some(ts) = &d.transfers {
            return Some(ts.as_slice());
        }
    }
    None
}

/// Extract range_proof hex string from either top-level or nested under data
fn extract_range_proof_hex(w: &WalletLikeTx) -> Option<&str> {
    if let Some(rp) = &w.range_proof {
        return Some(rp.as_str());
    }
    if let Some(d) = &w.data {
        if let Some(rp) = &d.range_proof {
            return Some(rp.as_str());
        }
    }
    None
}

/// Verify Bulletproof with commitments
fn verify_bp_with_commitments(range_proof: &[u8], commitments: &[[u8;32]]) -> bool {
    let Ok(rp) = RangeProof::from_bytes(range_proof) else { return false; };
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, commitments.len().max(1));
    let mut transcript = Transcript::new(b"XELIS_RangeProof_v1");
    let comms: Option<Vec<_>> = commitments.iter()
        .map(|c| CompressedRistretto::from_slice(c).expect("bad slice length").decompress())
        .collect();
    let Some(comms) = comms else { return false; };
    rp.verify_multiple(&bp_gens, &pc_gens, &mut transcript, &comms, 64).is_ok()
}

/// Compare POC TxSkeleton against a wallet-produced JSON (dev wallet or fixture).
/// Returns true if commitments and range_proof bytes match exactly.
/// Also verifies the wallet's Bulletproof independently for safety.
pub fn compare_with_wallet_json<P: AsRef<Path>>(skel: &TxSkeleton, wallet_json: P) -> anyhow::Result<()> {
    let raw = fs::read_to_string(wallet_json)?;
    let wtx: WalletLikeTx = serde_json::from_str(&raw)?;

    // 1) Pull the wallet commitments
    let w_transfers = extract_transfers(&wtx)
        .ok_or_else(|| anyhow::anyhow!("wallet JSON missing transfers"))?;
    if w_transfers.len() != skel.data_transfers.len() {
        anyhow::bail!("transfer count mismatch: wallet={} poc={}", w_transfers.len(), skel.data_transfers.len());
    }
    // decode wallet commitments
    let mut wallet_commitments = Vec::with_capacity(w_transfers.len());
    for (i, wt) in w_transfers.iter().enumerate() {
        let c = hex32(&wt.commitment)
            .ok_or_else(|| anyhow::anyhow!("transfer[{i}] commitment not 32-byte hex"))?;
        wallet_commitments.push(c);
    }

    // 2) Extract wallet range_proof bytes
    let rp_hex = extract_range_proof_hex(&wtx)
        .ok_or_else(|| anyhow::anyhow!("wallet JSON missing range_proof"))?;
    let wallet_rp = hex_to_vec(rp_hex)
        .ok_or_else(|| anyhow::anyhow!("range_proof must be hex"))?;

    // 3) Compare to our skeleton
    //    a) commitments (exact byte equality and same order)
    for (i, (wc, pc)) in wallet_commitments.iter().zip(skel.data_transfers.iter().map(|t| t.commitment)).enumerate() {
        if wc != &pc {
            anyhow::bail!("commitment mismatch at index {i}");
        }
    }
    //    b) range_proof exact bytes
    if wallet_rp != skel.range_proof {
        anyhow::bail!("range_proof bytes mismatch");
    }

    // 4) Sanity: verify the wallet's range proof independently
    if !verify_bp_with_commitments(&wallet_rp, &wallet_commitments) {
        anyhow::bail!("wallet range_proof failed independent verification");
    }

    // (Optional) Compare fee/nonce/reference if present
    if let Some(ref oref) = wtx.reference {
        if let Some(h) = hex32(&oref.hash) {
            if h != skel.reference.hash {
                anyhow::bail!("reference.hash mismatch");
            }
        }
        if oref.topoheight != 0 && oref.topoheight != skel.reference.topoheight {
            anyhow::bail!("reference.topoheight mismatch");
        }
    }
    if let Some(fee) = wtx.fee {
        if fee != skel.fee { anyhow::bail!("fee mismatch"); }
    }
    if let Some(nonce) = wtx.nonce {
        if nonce != skel.nonce { anyhow::bail!("nonce mismatch"); }
    }

    Ok(())
}
