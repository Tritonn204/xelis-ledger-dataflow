use anyhow::{bail, Context, Result};
use bulletproofs::RangeProof;
use curve25519_dalek::Scalar;
use xelis_common::{
    account::Nonce,
    crypto::{
        Hash, PublicKey, Signature,
        elgamal::{CompressedCommitment, CompressedHandle, CompressedPublicKey},
        proofs::{CommitmentEqProof, CiphertextValidityProof},
    },
    serializer::{Reader, Writer, Serializer},
    transaction::{
        Reference as XReference, SourceCommitment, TransferPayload,
        Transaction, TransactionType, TxVersion,
    },
};

use crate::types::TxSkeleton;

// 32 zero bytes as a "compressed commitment"
fn zero_compressed_commitment() -> CompressedCommitment {
    let z = [0u8; 32];
    let mut r = Reader::new(&z);
    CompressedCommitment::read(&mut r).expect("CompressedCommitment::read(zeros)")
}

// 192 zero bytes (3 points + 3 scalars) as a syntactically valid eq-proof
fn zero_eq_proof() -> CommitmentEqProof {
    let z = [0u8; 32 * 6];
    let mut r = Reader::new(&z);
    CommitmentEqProof::read(&mut r).expect("CommitmentEqProof::read(zeros)")
}

// Build a placeholder SourceCommitment so Transaction::read doesn’t fail on len==0.
// NOTE: purely structural; not cryptographically valid.
fn dummy_source_commitment(asset: &[u8; 32]) -> SourceCommitment {
    SourceCommitment::new(
        zero_compressed_commitment(),
        zero_eq_proof(),
        hash32(asset),
    )
}

#[inline] fn hash32(b: &[u8; 32]) -> Hash { let mut r = Reader::new(b); Hash::read(&mut r).expect("Hash::read") }
#[inline] fn comp_pk(b: &[u8; 32]) -> CompressedPublicKey { let mut r = Reader::new(b); CompressedPublicKey::read(&mut r).expect("CPK::read") }
#[inline] fn comp_commitment(b: &[u8; 32]) -> CompressedCommitment { let mut r = Reader::new(b); CompressedCommitment::read(&mut r).expect("CC::read") }
#[inline] fn comp_handle(b: &[u8; 32]) -> CompressedHandle { let mut r = Reader::new(b); CompressedHandle::read(&mut r).expect("CH::read") }
#[inline] fn range_proof_from_bytes(bytes: &[u8]) -> RangeProof { RangeProof::from_bytes(bytes).expect("RangeProof::from_bytes") }

fn read_ct_validity_proof(bytes: &[u8], version: TxVersion) -> Result<CiphertextValidityProof> {
    let mut r = Reader::new(bytes);
    // CiphertextValidityProof::read expects version in Reader context
    r.context_mut().store(version);
    CiphertextValidityProof::read(&mut r).context("CiphertextValidityProof::read")
}

fn read_eq_proof(bytes: &[u8]) -> Result<CommitmentEqProof> {
    let mut r = Reader::new(bytes);
    CommitmentEqProof::read(&mut r).context("CommitmentEqProof::read")
}

pub fn canonical_roundtrip_bytes_with_ct(
    skel: &TxSkeleton,
    ct_proofs: Vec<CiphertextValidityProof>,
) -> anyhow::Result<Vec<u8>> {
    use anyhow::{bail, Context};
    use xelis_common::{
        account::Nonce,
        crypto::{elgamal::{CompressedCommitment, CompressedHandle, CompressedPublicKey}, Hash, Signature},
        serializer::{Reader, Writer, Serializer},
        transaction::{Reference as XReference, Transaction, TransactionType, TransferPayload, TxVersion},
    };
    use bulletproofs::RangeProof;
    use curve25519_dalek::Scalar;

    #[inline] fn hash32(b: &[u8; 32]) -> Hash { let mut r = Reader::new(b); Hash::read(&mut r).expect("Hash::read") }
    #[inline] fn comp_pk(b: &[u8; 32]) -> CompressedPublicKey { let mut r = Reader::new(b); CompressedPublicKey::read(&mut r).expect("CPK::read") }
    #[inline] fn comp_commitment(b: &[u8; 32]) -> CompressedCommitment { let mut r = Reader::new(b); CompressedCommitment::read(&mut r).expect("CC::read") }
    #[inline] fn comp_handle(b: &[u8; 32]) -> CompressedHandle { let mut r = Reader::new(b); CompressedHandle::read(&mut r).expect("CH::read") }
    #[inline] fn range_proof_from_bytes(bytes: &[u8]) -> RangeProof { RangeProof::from_bytes(bytes).expect("RangeProof::from_bytes") }

    let version = TxVersion::V1;

    if ct_proofs.len() != skel.data_transfers.len() {
        bail!("ct_proofs len mismatch (got {}, need {})", ct_proofs.len(), skel.data_transfers.len());
    }

    // Build transfers by zipping your outputs with the actual proof objects
    let transfers: Vec<TransferPayload> = skel
        .data_transfers
        .iter()
        .zip(ct_proofs.into_iter())
        .map(|(t, proof)| {
            TransferPayload::new(
                hash32(&t.asset),
                comp_pk(&t.destination),
                /* extra_data */ None,
                comp_commitment(&t.commitment),
                comp_handle(&t.sender_handle),
                comp_handle(&t.receiver_handle),
                proof,
            )
        })
        .collect();

    // No source commitments yet (ok for serializer test)
    let tx = Transaction::new(
        version,
        comp_pk(&skel.source),
        TransactionType::Transfers(transfers),
        skel.fee,
        Nonce::from(skel.nonce),
        vec![], // source commitments later
        range_proof_from_bytes(&skel.range_proof),
        XReference { hash: hash32(&skel.reference.hash), topoheight: skel.reference.topoheight },
        None,
        Signature::new(Scalar::ZERO, Scalar::ZERO),
    );

    // write → read → write and compare
    let mut bytes = Vec::new();
    { let mut w = Writer::new(&mut bytes); tx.write(&mut w); }

    let mut r = Reader::new(bytes.as_slice());
    let parsed = Transaction::read(&mut r).context("Transaction::read")?;

    let mut bytes2 = Vec::new();
    { let mut w2 = Writer::new(&mut bytes2); parsed.write(&mut w2); }

    if bytes != bytes2 {
        bail!("canonical re-serialize mismatch");
    }
    Ok(bytes)
}

/// 1) Round-trip a single CT proof object by itself (serialize -> read)
pub fn debug_roundtrip_ct_proof(proof: &CiphertextValidityProof) -> Result<()> {
    let mut buf = Vec::new();
    { let mut w = Writer::new(&mut buf); proof.write(&mut w); }
    let mut r = Reader::new(buf.as_slice());
    // IMPORTANT: CT proof read expects the tx version in the reader context
    r.context_mut().store(TxVersion::V1);
    let _p2 = CiphertextValidityProof::read(&mut r).context("CiphertextValidityProof::read")?;
    Ok(())
}

/// 2) Round-trip a single TransferPayload with a provided proof
pub fn debug_roundtrip_transfer_payload(
    asset: &[u8;32],
    dest: &[u8;32],
    commitment: &[u8;32],
    sender_handle: &[u8;32],
    receiver_handle: &[u8;32],
    proof: CiphertextValidityProof,
) -> Result<()> {
    let payload = TransferPayload::new(
        hash32(asset),
        comp_pk(dest),
        /* extra_data */ None,
        comp_commitment(commitment),
        comp_handle(sender_handle),
        comp_handle(receiver_handle),
        proof,
    );
    let mut buf = Vec::new();
    { let mut w = Writer::new(&mut buf); payload.write(&mut w); }
    let mut r = Reader::new(buf.as_slice());
    // Again, TransferPayload::read -> CTProof::read expects version in context
    r.context_mut().store(TxVersion::V1);
    let _p2 = TransferPayload::read(&mut r).context("TransferPayload::read")?;
    Ok(())
}

/// 3) Canonical TX round-trip with objects (adds prints + context push before read)
pub fn canonical_roundtrip_bytes_with_ct_verbose(
    skel: &crate::types::TxSkeleton,
    ct_proofs: Vec<CiphertextValidityProof>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    use anyhow::{bail, Context, Result};
    use xelis_common::{
        account::Nonce,
        crypto::Signature,
        serializer::{Reader, Writer, Serializer},
        transaction::{
            builder::UnsignedTransaction,
            Reference as XReference,
            Transaction, TransactionType, TransferPayload, TxVersion,
        },
    };
    use curve25519_dalek::Scalar;

    if ct_proofs.len() != skel.data_transfers.len() {
        bail!(
            "ct_proofs len mismatch (got {}, need {})",
            ct_proofs.len(),
            skel.data_transfers.len()
        );
    }

    // A) Prove single CT proof object round-trips by itself
    debug_roundtrip_ct_proof(&ct_proofs[0]).context("CT proof[0] self round-trip failed")?;

    // B) Prove a TransferPayload with a CT proof round-trips
    let t0 = &skel.data_transfers[0];
    debug_roundtrip_transfer_payload(
        &t0.asset,
        &t0.destination,
        &t0.commitment,
        &t0.sender_handle,
        &t0.receiver_handle,
        ct_proofs[0].clone(),
    )
    .context("TransferPayload[0] round-trip failed")?;

    // C) Build transfers twice (once for TX, once for Unsigned), reusing the same proofs.
    //    We don't consume ct_proofs; we iterate by reference and clone each proof.
    let transfers_tx: Vec<TransferPayload> = skel
        .data_transfers
        .iter()
        .zip(ct_proofs.iter().cloned())
        .map(|(t, proof)| {
            TransferPayload::new(
                hash32(&t.asset),
                comp_pk(&t.destination),
                /* extra_data */ None,
                comp_commitment(&t.commitment),
                comp_handle(&t.sender_handle),
                comp_handle(&t.receiver_handle),
                proof,
            )
        })
        .collect();

    let transfers_unsigned: Vec<TransferPayload> = skel
        .data_transfers
        .iter()
        .zip(ct_proofs.iter().cloned())
        .map(|(t, proof)| {
            TransferPayload::new(
                hash32(&t.asset),
                comp_pk(&t.destination),
                /* extra_data */ None,
                comp_commitment(&t.commitment),
                comp_handle(&t.sender_handle),
                comp_handle(&t.receiver_handle),
                proof,
            )
        })
        .collect();

    // D) Add one placeholder SourceCommitment so Transaction::read passes size checks
    let mut scs = Vec::with_capacity(1);
    let first_asset = skel
        .data_transfers
        .first()
        .map(|t| t.asset)
        .unwrap_or([0u8; 32]);
    scs.push(dummy_source_commitment(&first_asset));

    // E) Build the Transaction (with placeholder Signature)
    let tx = Transaction::new(
        TxVersion::V1,
        comp_pk(&skel.source),
        TransactionType::Transfers(transfers_tx),
        skel.fee,
        Nonce::from(skel.nonce),
        scs.clone(),
        range_proof_from_bytes(&skel.range_proof),
        XReference {
            hash: hash32(&skel.reference.hash),
            topoheight: skel.reference.topoheight,
        },
        None,
        Signature::new(Scalar::ZERO, Scalar::ZERO),
    );

    // F) Serialize TX
    let mut tx_bytes = Vec::new();
    {
        let mut w = Writer::new(&mut tx_bytes);
        tx.write(&mut w);
    }
    println!("TX serialize ok ({} bytes)", tx_bytes.len());

    // G) Read TX (push version just to be safe), then re-serialize and compare
    let mut r = Reader::new(tx_bytes.as_slice());
    r.context_mut().store(TxVersion::V1);
    let parsed = Transaction::read(&mut r).context("Transaction::read")?;
    println!("TX read ok");

    let mut tx_bytes2 = Vec::new();
    {
        let mut w2 = Writer::new(&mut tx_bytes2);
        parsed.write(&mut w2);
    }
    println!("TX re-serialize ok ({} bytes)", tx_bytes2.len());
    if tx_bytes != tx_bytes2 {
        bail!("canonical re-serialize mismatch");
    }

    // H) Build the UnsignedTransaction (expected device preimage in many designs)
    //    UnsignedTransaction::new expects a CompressedPublicKey for 'source';
    //    we already operate on 32-byte compressed keys, so reuse comp_pk(..).
    let unsigned = UnsignedTransaction::new(
        TxVersion::V1,
        comp_pk(&skel.source),
        TransactionType::Transfers(transfers_unsigned),
        skel.fee,
        Nonce::from(skel.nonce),
        scs,
        XReference {
            hash: hash32(&skel.reference.hash),
            topoheight: skel.reference.topoheight,
        },
        range_proof_from_bytes(&skel.range_proof),
    );

    // I) Serialize UnsignedTransaction (this is the typical device preimage)
    let unsigned_bytes = unsigned.to_bytes();
    println!("Unsigned serialize ok ({} bytes)", unsigned_bytes.len());

    // Return (unsigned_bytes, tx_bytes)
    Ok((unsigned_bytes, tx_bytes))
}

/// Hex helper
fn hex32(b: &[u8; 32]) -> String { hex::encode(b) }

use anyhow::anyhow;
use curve25519_dalek::RistrettoPoint;
use xelis_common::crypto::elgamal::G;
use xelis_common::crypto::proofs::H;
use crate::types::TransferSketch;

pub fn verify_commitments_on_skeleton(
    skel: &TxSkeleton,
    amounts: &[u64],
    blinders_le: &[[u8; 32]],
) -> Result<()> {
    let n = skel.data_transfers.len();
    if amounts.len() != n {
        return Err(anyhow!("amounts len mismatch: got {}, need {}", amounts.len(), n));
    }
    if blinders_le.len() != n {
        return Err(anyhow!("blinders len mismatch: got {}, need {}", blinders_le.len(), n));
    }

    println!("▶ Verifying {} output commitment(s)…", n);

    for (i, t) in skel.data_transfers.iter().enumerate() {
        let v = Scalar::from(amounts[i]);                         // u64 → Scalar (LE)
        let r = Scalar::from_bytes_mod_order(blinders_le[i]);     // LE bytes → Scalar

        let v = Scalar::from(amounts[i]);
        let r = Scalar::from_bytes_mod_order(blinders_le[i]);

        
        // Device-style “splayed” math: vg = v*G, rh = r*H, C = vg + rh
        // (dalek implements Scalar * RistrettoPoint)
        let vg: RistrettoPoint = v * G;
        let rh: RistrettoPoint = r * *H;

        println!("      vg = {}",   hex::encode(vg.compress().as_bytes()));
        println!("      rh   = {}", hex::encode(rh.compress().as_bytes()));

        let c_point: RistrettoPoint = vg + rh;

        let c_can = c_point.compress().to_bytes();

        let want = t.commitment; // canonical 32B from your skeleton
        let ok = c_can == want;

        println!("  [{}] amount={}  blinder={}...", i, amounts[i], hex32(&blinders_le[i]));
        println!("      C_calc = {}", hex::encode(c_can));
        println!("      C_tx   = {}", hex::encode(want));

        if !ok {
            println!("✗ mismatch at output {}", i);
            return Err(anyhow!("commitment mismatch at index {}", i));
        } else {
            println!("✓ output {} OK", i);
        }
    }

    println!("✔ All commitments verified");
    Ok(())
}

/// Convenience wrapper if you have the sketches alongside the skeleton.
/// Uses `skel.output_blinders` and `sketches[i].amount` in the same order.
pub fn verify_commitments_with_sketches(
    skel: &TxSkeleton,
    sketches: &[TransferSketch],
) -> Result<()> {
    let n = skel.data_transfers.len();
    if sketches.len() != n {
        return Err(anyhow!("sketches len mismatch: got {}, need {}", sketches.len(), n));
    }
    if skel.output_blinders.len() != n {
        return Err(anyhow!("output_blinders len mismatch: got {}, need {}", skel.output_blinders.len(), n));
    }
    let amounts: Vec<u64> = sketches.iter().map(|s| s.amount).collect();
    verify_commitments_on_skeleton(skel, &amounts, &skel.output_blinders)
}