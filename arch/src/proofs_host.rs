use anyhow::{bail, Context, Result};
use curve25519_dalek::Scalar;
use merlin::Transcript;
use xelis_common::{
    crypto::{
        elgamal::{CompressedPublicKey, PedersenOpening, PublicKey},
        proofs::CiphertextValidityProof,
    },
    serializer::{Reader, Writer, Serializer},
};

use crate::types::TxSkeleton;

/// Read a CompressedPublicKey from 32 bytes and decompress to PublicKey.
fn read_pubkey(bytes: &[u8; 32]) -> Result<PublicKey> {
    let mut r = Reader::new(bytes);
    let cpk = CompressedPublicKey::read(&mut r)?;
    cpk.decompress().context("pubkey decompress failed")
}

/// Build per-output CiphertextValidityProof objects (does not mutate the skeleton).
/// IMPORTANT: For TxVersion >= V1, proofs must include Y_2, which requires the **source pubkey**.
pub fn build_ct_validity_proofs(skel: &TxSkeleton, amounts: &[u64]) -> Result<Vec<CiphertextValidityProof>> {
    let n = skel.data_transfers.len();
    if amounts.len() != n || skel.output_blinders.len() != n {
        bail!(
            "length mismatch: transfers={}, amounts={}, blinders={}",
            n, amounts.len(), skel.output_blinders.len()
        );
    }

    // Decompress the transaction source (sender) public key once
    let source_pk = read_pubkey(&skel.source)?;

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let t = &skel.data_transfers[i];

        // destination pubkey (compressed 32 → PublicKey)
        let dest_pk = read_pubkey(&t.destination)?;

        // opening from the stored blinder
        let b = skel.output_blinders[i];
        let blind = Scalar::from_canonical_bytes(b).unwrap_or_else(|| Scalar::from_bytes_mod_order(b));
        let opening = PedersenOpening::from_scalar(blind);

        // domain sep for the proof transcript (same one wallet/core uses for tx proofs)
        let mut transcript = Transcript::new(b"XELIS_Tx");

        // Build the proof with **Some(&source_pk)** so Y_2 is present for V1
        let proof = CiphertextValidityProof::new(&dest_pk, Some(&source_pk), amounts[i], &opening, &mut transcript);
        out.push(proof);
    }
    Ok(out)
}

/// Fill each transfer’s `ct_validity_proof_bytes` with the serialized proof (for fixtures/JSON).
pub fn fill_ct_validity_proofs(skel: &mut TxSkeleton, amounts: &[u64]) -> Result<()> {
    let proofs = build_ct_validity_proofs(skel, amounts)?;
    for (t, proof) in skel.data_transfers.iter_mut().zip(proofs.into_iter()) {
        let mut buf = Vec::new();
        { let mut w = Writer::new(&mut buf); proof.write(&mut w); }
        t.ct_validity_proof_bytes = buf;
    }
    Ok(())
}
