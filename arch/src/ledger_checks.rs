use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{scalar::Scalar, ristretto::CompressedRistretto};
use merlin::Transcript;
use sha2::{Digest, Sha512};
use crate::types::*;

/// Device recomputes commitments + validates compressed points.
pub fn verify_outputs_match_commitments(skel: &TxSkeleton, amounts: &[u64]) -> bool {
    if amounts.len() != skel.data_transfers.len() || amounts.len() != skel.output_blinders.len() {
        return false;
    }
    let gens = PedersenGens::default();
    for ((amt, blind_bytes), tx_out) in amounts.iter()
        .zip(&skel.output_blinders)
        .zip(&skel.data_transfers)
    {
        // prefer canonical decode; fallback to mod reduction if needed
        let blinding = Scalar::from_canonical_bytes(*blind_bytes)
            .unwrap_or_else(|| Scalar::from_bytes_mod_order(*blind_bytes));

        let recomputed = gens.commit((*amt).into(), blinding).compress().to_bytes();

        if CompressedRistretto::from_slice(&tx_out.commitment).expect("Invalid Commitment").decompress().is_none() {
            return false;
        }
        if recomputed != tx_out.commitment { return false; }
    }
    true
}

/// Verify the Bulletproof(s) we built (host or device-side demo check).
pub fn verify_range_proof_bytes(range_proof_bytes: &[u8], commitments: &[[u8;32]]) -> bool {
    let Ok(rp) = RangeProof::from_bytes(range_proof_bytes) else { return false; };
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, commitments.len().max(1));
    let mut transcript = Transcript::new(b"XELIS_RangeProof_v1");
    let comms: Vec<_> = commitments.iter()
        .map(|c| CompressedRistretto::from_slice(c).expect("Invalid Commitment").decompress())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if comms.len() != commitments.len() { return false; }
    rp.verify_multiple(&bp_gens, &pc_gens, &mut transcript, &comms, 64).is_ok()
}

/// Bind signature to semantics + proof bytes (demo digest).
/// Later, replace with canonical XELIS serialization via xelis_common::serializer.
pub fn digest_for_signing_demo(skel: &TxSkeleton) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(&skel.source);
    hasher.update(&skel.reference.hash);
    hasher.update(&skel.reference.topoheight.to_le_bytes());
    hasher.update(&skel.fee.to_le_bytes());
    hasher.update(&skel.nonce.to_le_bytes());
    for t in &skel.data_transfers {
        hasher.update(&t.asset);
        hasher.update(&t.commitment);
        hasher.update(&t.destination);
        if let Some(extra) = &t.extra_data { hasher.update(extra); }
    }
    hasher.update(&skel.range_proof);
    for sc in &skel.source_commitments {
        hasher.update(&sc.asset);
        hasher.update(&sc.commitment);
        hasher.update(&sc.proof.Y_0);
        hasher.update(&sc.proof.Y_1);
        hasher.update(&sc.proof.Y_2);
        hasher.update(&sc.proof.z_r);
        hasher.update(&sc.proof.z_s);
        hasher.update(&sc.proof.z_x);
    }
    hasher.finalize().into()
}
