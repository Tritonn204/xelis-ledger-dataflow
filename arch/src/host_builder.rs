use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;

use crate::types::*;

fn pedersen_commit_bytes(v: u64, blinding: Scalar, gens: &PedersenGens) -> [u8; 32] {
    gens.commit(Scalar::from(v), blinding).compress().to_bytes()
}

fn dummy_ct_proof() -> CtValidityProof {
    CtValidityProof { Y_0: [0;32], Y_1: [0;32], z_r: [0;32], z_x: [0;32] }
}

/// Build commitments + Bulletproof(s); returns a `TxSkeleton` (no signature).
pub fn build_tx_skeleton_host(
    transfers: &[TransferSketch],
    fee: u64,
    nonce: u64,
    source_pubkey: [u8; 32],
    reference: Reference,
) -> TxSkeleton {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, transfers.len().max(1));

    // 1) choose blinders (later: derive from device if you want)
    let mut rng = OsRng;
    let blinders: Vec<Scalar> = transfers.iter().map(|_| Scalar::random(&mut rng)).collect();

    // 2) output commitments (+ placeholder ct proofs)
    let mut commits = Vec::with_capacity(transfers.len());
    let mut rp_values = Vec::with_capacity(transfers.len());
    let mut rp_blinders = Vec::with_capacity(transfers.len());

    for (t, b) in transfers.iter().zip(&blinders) {
        let c_bytes = pedersen_commit_bytes(t.amount, *b, &pc_gens);
        commits.push(TransferCommit {
            asset: t.asset,
            commitment: c_bytes,
            ct_validity_proof: dummy_ct_proof(), // TODO: real proof
            destination: t.destination_pub,
            extra_data: t.extra_data.clone(),
            receiver_handle: [0u8; 32], // TODO: Twisted ElGamal enc.
            sender_handle:   [0u8; 32], // TODO
            ct_validity_proof_bytes: Vec::new(),
        });
        rp_values.push(t.amount);
        rp_blinders.push(*b);
    }

    // 3) global Bulletproof(s) range proof
    let mut transcript = Transcript::new(b"XELIS_RangeProof_v1");
    let (rp, _coms) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &rp_values,
        &rp_blinders,
        64,
    ).expect("range proof");

    // 4) per-asset source commitments (TODO host-side)
    let source_commitments = vec![];

    TxSkeleton {
        data_transfers: commits,
        range_proof: rp.to_bytes(),
        source_commitments,
        fee,
        nonce,
        source: source_pubkey,
        reference,
        output_blinders: blinders.iter().map(|s| s.to_bytes()).collect(),
    }
}
