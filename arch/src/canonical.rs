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
) -> Result<Vec<u8>> {
    use xelis_common::{account::Nonce, crypto::Signature};

    if ct_proofs.len() != skel.data_transfers.len() {
        bail!("ct_proofs len mismatch (got {}, need {})", ct_proofs.len(), skel.data_transfers.len());
    }

    // A) Prove single CT proof object round-trips
    debug_roundtrip_ct_proof(&ct_proofs[0]).context("CT proof[0] self round-trip failed")?;

    // B) Prove first transfer payload round-trips
    let t0 = &skel.data_transfers[0];
    debug_roundtrip_transfer_payload(
        &t0.asset, &t0.destination, &t0.commitment, &t0.sender_handle, &t0.receiver_handle, ct_proofs[0].clone()
    ).context("TransferPayload[0] round-trip failed")?;

    // C) Build transfers for the TX using the proof objects
    let transfers: Vec<TransferPayload> = skel
        .data_transfers
        .iter()
        .zip(ct_proofs.into_iter())
        .map(|(t, proof)| {
            TransferPayload::new(
                hash32(&t.asset),
                comp_pk(&t.destination),
                None,
                comp_commitment(&t.commitment),
                comp_handle(&t.sender_handle),
                comp_handle(&t.receiver_handle),
                proof,
            )
        })
        .collect();

    // D) Add exactly one placeholder SourceCommitment so Transaction::read passes size checks
    let mut scs = Vec::with_capacity(1);
    let first_asset = skel.data_transfers.first().map(|t| t.asset).unwrap_or([0u8;32]);
    scs.push(dummy_source_commitment(&first_asset));

    // E) Build Transaction
    let tx = Transaction::new(
        TxVersion::V1,
        comp_pk(&skel.source),
        TransactionType::Transfers(transfers),
        skel.fee,
        Nonce::from(skel.nonce),
        scs, // <-- at least one SC
        range_proof_from_bytes(&skel.range_proof),
        XReference { hash: hash32(&skel.reference.hash), topoheight: skel.reference.topoheight },
        None,
        Signature::new(Scalar::ZERO, Scalar::ZERO),
    );

    // F) Serialize TX
    let mut bytes = Vec::new();
    { let mut w = Writer::new(&mut bytes); tx.write(&mut w); }
    println!("TX serialize ok ({} bytes)", bytes.len());

    // G) Read TX (push version into context just to be safe)
    let mut r = Reader::new(bytes.as_slice());
    r.context_mut().store(TxVersion::V1);
    let parsed = Transaction::read(&mut r).context("Transaction::read")?;
    println!("TX read ok");

    // H) Re-serialize parsed and compare
    let mut bytes2 = Vec::new();
    { let mut w2 = Writer::new(&mut bytes2); parsed.write(&mut w2); }
    println!("TX re-serialize ok ({} bytes)", bytes2.len());

    if bytes != bytes2 {
        bail!("canonical re-serialize mismatch");
    }
    Ok(bytes)
}