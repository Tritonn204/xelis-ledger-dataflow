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
    // Special case for burns - no range proofs needed
    if transfers.len() == 1 && transfers[0].extra_data.is_none() {
        // Might be a burn, return minimal skeleton
        // You'll need to add burn detection logic here
    }
    
    let pc_gens = PedersenGens::default();
    
    // Calculate padded size for Bulletproof generation
    let actual_size = transfers.len();
    let padded_size = actual_size.next_power_of_two();
    
    // BulletproofGens needs the padded capacity
    let bp_gens = BulletproofGens::new(64, padded_size);

    // 1) Generate blinders for actual outputs
    let mut rng = OsRng;
    let mut blinders: Vec<Scalar> = transfers.iter()
        .map(|_| Scalar::random(&mut rng))
        .collect();

    // 2) Build actual output commitments
    let mut commits = Vec::with_capacity(transfers.len());
    let mut rp_values = Vec::with_capacity(padded_size);
    let mut rp_blinders = Vec::with_capacity(padded_size);

    // Process real transfers
    for (t, b) in transfers.iter().zip(&blinders) {
        let c_bytes = pedersen_commit_bytes(t.amount, *b, &pc_gens);
        commits.push(TransferCommit {
            asset: t.asset,
            commitment: c_bytes,
            ct_validity_proof: dummy_ct_proof(),
            destination: t.destination_pub,
            extra_data: t.extra_data.clone(),
            receiver_handle: [0u8; 32],
            sender_handle: [0u8; 32],
            ct_validity_proof_bytes: Vec::new(),
        });
        rp_values.push(t.amount);
        rp_blinders.push(*b);
    }

    // 3) Pad for range proof if needed
    if padded_size > actual_size {
        // Add padding: zero amounts with random blinders
        for _ in actual_size..padded_size {
            let padding_blinder = Scalar::random(&mut rng);
            rp_values.push(0);  // Zero amount
            rp_blinders.push(padding_blinder);
            // Note: We do NOT add these to blinders vec or commits
            // They're only for proof generation
        }
    }

    // 4) Generate range proof with padded inputs
    let mut transcript = Transcript::new(b"XELIS_RangeProof_v1");
    let (rp, _coms) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &rp_values,     // Includes padding
        &rp_blinders,   // Includes padding
        64,
    ).expect("range proof");

    // 5) Return skeleton with only actual outputs
    TxSkeleton {
        data_transfers: commits,  // Only real transfers
        range_proof: rp.to_bytes(),
        source_commitments: vec![],
        fee,
        nonce,
        source: source_pubkey,
        reference,
        output_blinders: blinders.iter().map(|s| s.to_bytes()).collect(), // Only real blinders
    }
}