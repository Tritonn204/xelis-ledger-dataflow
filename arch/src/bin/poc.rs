use debugger::{types::*, host_builder::build_tx_skeleton_host, ledger_checks::*, wallet_compare::compare_with_wallet_json};
use debugger::proofs_host::{fill_ct_validity_proofs, build_ct_validity_proofs};
use debugger::canonical::{canonical_roundtrip_bytes_with_ct, canonical_roundtrip_bytes_with_ct_verbose};

// ─────────────────────────────────────────────────────────────────────────────
// Demo key material (valid compressed Ristretto pubkeys).
// In a real wallet:
//
//  • SOURCE pubkey comes from the user’s account (view/spend key derivations).
//    - The *private* spend key never leaves the Ledger; only its *public*
//      key (compressed) is used on the host when non-secret ops need it.
//
//  • DESTINATION pubkeys come from recipients (addresses → decode → dest PK).
// ─────────────────────────────────────────────────────────────────────────────
const KEY_P1_SRC: [u8; 32] = [
    140, 146,  64, 180,  86, 169, 230, 220,
    101, 195, 119, 161,   4, 141, 116,  95,
    148, 160, 140, 219, 127,  68, 203, 205,
    123,  70, 243,  64,  72, 135,  17,  52,
];

const KEY_P2_DST: [u8; 32] = [
    240,  91, 193, 223,  40,  49, 113, 124,
     41, 146, 216,  91,  87, 224, 207,  61,
     18,  63, 214, 194,  84,  37, 125, 229,
    247, 132, 190,  54, 151,  71, 178,  73,
];

const KEY_PFF_DST: [u8; 32] = [
    246, 222, 207, 191, 158, 250, 188, 138,
    165, 148,  82, 170,  87,  12, 184,  78,
    237, 127, 207, 202, 125, 174, 165, 138,
    147, 185,  52,  68,  64,  10, 122, 115,
];

fn main() {
    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Draft “what the user wants to send”
    //
    // In a real wallet UI this comes from screens/forms:
    //   - A set of (amount, asset, destination, optional memo)
    //   - Fee strategy & explicit nonce/reference (or fetched from daemon)
    //
    // Nothing here requires secrets; this is all host-side.
    // ─────────────────────────────────────────────────────────────────────────
    let transfers = vec![
        TransferSketch { amount: 12_345, asset: [1u8; 32], destination_pub: KEY_P2_DST,  extra_data: None },
        TransferSketch { amount: 67_890, asset: [3u8; 32], destination_pub: KEY_PFF_DST, extra_data: Some(vec![0xAA, 0xBB]) },
    ];
    let fee = 1100;
    let nonce = 42;
    let source_pubkey = KEY_P1_SRC;                            // (public only; no secrets here)
    let reference = Reference { hash: [7u8; 32], topoheight: 123_456 };

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Build a TxSkeleton (commitments + BP transcript input)
    //
    // This function:
    //   • Mints per-output Pedersen commitments: C_i = v_i*G + r_i*H
    //   • (In our POC) stores the blinders r_i for proof building
    //   • Constructs and serializes a Bulletproof range proof over {v_i}
    //   • Copies through fee/nonce/reference/source
    //
    // This is heavy compute/memory → stays on HOST, not Ledger.
    // ─────────────────────────────────────────────────────────────────────────
    let mut skel = build_tx_skeleton_host(&transfers, fee, nonce, source_pubkey, reference);

    println!("Built TxSkeleton:");
    println!("  outputs: {}", skel.data_transfers.len());
    println!("  range_proof bytes: {}", skel.range_proof.len());
    println!("  fee: {}, nonce: {}", skel.fee, skel.nonce);

    // ─────────────────────────────────────────────────────────────────────────
    // [LEDGER (verifier-style) CHECKS, but performed here on HOST]
    //
    // The Ledger *doesn’t* recompute proofs; it only verifies the host feed:
    //   • Recompute commitments from (amounts, recorded blinders) and
    //     check they match bytes we plan to put on-chain.
    //   • Verify Bulletproof bytes against the output commitments.
    //
    // In the real app you’ll either:
    //   (A) do these checks on HOST for dev confidence, or
    //   (B) expose a lightweight APDU to let the Ledger recompute just enough
    //       to “attest” to what it’s about to sign (optional).
    // ─────────────────────────────────────────────────────────────────────────
    let amounts: Vec<u64> = transfers.iter().map(|t| t.amount).collect();

    // This mirrors the *on-device* attestation you’ll do before signing:
    let ok = verify_outputs_match_commitments(&skel, &amounts);
    println!("[DEVICE-STYLE] commitment check (host-sim): {}", ok);

    // This is a host-only dev sanity check; do not implement on device:
    let rp_ok = verify_range_proof_bytes(&skel.range_proof, &commitments);
    println!("[HOST-DEV] range proof verifies: {}", rp_ok);

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Build per-output Ciphertext-Validity proofs (CT proofs)
    //
    // For TxVersion >= V1 Xelis expects Y₂ (i.e., the proof *must* bind the
    // source pubkey). Critically, this still does not require the spend key —
    // the construction uses public keys, amounts, and the Pedersen opening r_i.
    //
    // => Heavy math again → stays on HOST.
    // ─────────────────────────────────────────────────────────────────────────
    let ct_objs = match build_ct_validity_proofs(&skel, &amounts) {
        Ok(v) => v, // proof *objects* (we also have a fill_* to store raw bytes for fixtures)
        Err(e) => { eprintln!("CT proof build failed: {e}"); return; }
    };

    // Optional: also serialize the CT proofs into the skeleton for JSON fixtures
    // (Useful when producing wallet-like JSON or parity tests.)
    if let Err(e) = fill_ct_validity_proofs(&mut skel, &amounts) {
        eprintln!("CT proof fill failed: {e}");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] “demo digest”: this is *not* the canonical signing preimage.
    // We keep it for quick sanity. The *canonical* preimage is derived below
    // by serializing the real `Transaction` via xelis_common.
    // ─────────────────────────────────────────────────────────────────────────
    let digest = digest_for_signing_demo(&skel);
    println!("Digest for signing (BLAKE3): {}", hex::encode(digest));

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Canonical (Core) serialization round-trip with proof objects
    //
    // This does three things:
    //   1) Assemble a real `Transaction` (Transfers variant) using:
    //        - commitments, CT proofs, fee/nonce/reference, source pk, range proof
    //        - (For now) a *placeholder* SourceCommitment to satisfy size rules
    //          — purely structural for the serializer test; not cryptographically valid.
    //   2) Serialize → Read → Re-serialize, asserting byte-for-byte equality.
    //   3) Emit the *canonical pre-signature bytes* and a deterministic digest.
    //
    // This proves the host can produce the exact blob the Ledger should sign.
    // ─────────────────────────────────────────────────────────────────────────
    match canonical_roundtrip_bytes_with_ct_verbose(&skel, ct_objs) {
        Ok(bytes) => {
            println!("Canonical pre-sig bytes: {}", bytes.len());

            // ─────────────────────────────────────────────────────────────────
            // [LEDGER] The device receives exactly `bytes` (or its hash),
            // displays human-readable fields (amounts, fee, destinations),
            // and signs the canonical preimage with the spend key.
            //
            // → The host then inserts the signature into the `Transaction`
            //   and broadcasts to the daemon.
            // ─────────────────────────────────────────────────────────────────
            println!("Canonical digest (BLAKE3 over pre-sig): {}", hex::encode(blake3::hash(&bytes).as_bytes()));
        }
        Err(e) => eprintln!("Canonical round-trip (verbose): {e:#}"),
    }

    // (Optional) If you also want wallet-JSON parity:
    //  - Use `wallet_json::skel_to_wallet_json(&skel)` to emit a wallet-like JSON
    //  - Then `compare_with_wallet_json(&skel, "wallet_tx.json")` to assert 1:1 fields.
}
