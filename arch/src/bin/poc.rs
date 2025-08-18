use debugger::{types::*, host_builder::build_tx_skeleton_host, ledger_checks::*, wallet_compare::compare_with_wallet_json};
use debugger::proofs_host::{fill_ct_validity_proofs, build_ct_validity_proofs};
use debugger::canonical::{canonical_roundtrip_bytes_with_ct, canonical_roundtrip_bytes_with_ct_verbose};
use debugger::binary::{build_preview_memo, write_bundle};

use std::fs;
use std::path::Path;
use std::io::{self, Write};
use rand::{thread_rng, Rng};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

/// Write bytes to a file (create parent dirs if needed)
fn dump_bytes(path: &str, bytes: &[u8]) {
    if let Some(parent) = Path::new(path).parent() { let _ = fs::create_dir_all(parent); }
    fs::write(path, bytes).expect("write dump");
    println!("wrote {}", path);
}

/// Generate a random valid Ristretto keypair
fn generate_random_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = thread_rng();
    let mut scalar_bytes = [0u8; 32];
    rng.fill(&mut scalar_bytes);
    
    // Create scalar from random bytes
    let private_key = Scalar::from_bytes_mod_order(scalar_bytes);
    
    // Derive public key: P = s*G
    let public_point: RistrettoPoint = private_key * RISTRETTO_BASEPOINT_POINT;
    let public_key = public_point.compress();
    
    (scalar_bytes, public_key.to_bytes())
}

/// Generate a random asset ID (just random 32 bytes)
fn generate_random_asset() -> [u8; 32] {
    let mut rng = thread_rng();
    let mut asset = [0u8; 32];
    rng.fill(&mut asset);
    asset
}

/// Get user input with a prompt
fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Get a number from user with validation
fn prompt_number(msg: &str, min: u64, max: u64) -> u64 {
    loop {
        let input = prompt(msg);
        match input.parse::<u64>() {
            Ok(n) if n >= min && n <= max => return n,
            _ => println!("Please enter a number between {} and {}", min, max),
        }
    }
}

fn main() {
    println!("═══════════════════════════════════════════════════════════════");
    println!("    Xelis Transaction Generator Wizard");
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    // Generate source keypair
    let (source_private, source_pubkey) = generate_random_keypair();
    println!("Generated source keypair:");
    println!("  Public:  {}", hex::encode(&source_pubkey));
    println!("  Private: {} (not used in host)", hex::encode(&source_private));
    println!();

    // Choose transaction type
    println!("Select transaction type:");
    println!("  1) Transfer");
    println!("  2) Burn");
    let tx_type = prompt_number("Enter choice (1-2): ", 1, 2);
    
    // Generate transfers/burns based on type
    let transfers = match tx_type {
        1 => {
            // Transfer flow
            let output_count = prompt_number("How many outputs? (1-256): ", 1, 256) as usize;
            let mut transfers = Vec::new();
            
            println!("\nGenerating {} random transfers...", output_count);
            for i in 0..output_count {
                let mut rng = thread_rng();
                
                // Random amount between 100 and 1_000_000
                let amount = rng.gen_range(100..=1_000_000);
                
                // Random asset or native (0x00...)
                let asset = if rng.gen_bool(0.7) {
                    [0u8; 32] // 70% chance of native asset
                } else {
                    generate_random_asset()
                };
                
                // Random destination
                let (_, dest_pub) = generate_random_keypair();
                
                // Optional extra data (20% chance)
                let extra_data = if rng.gen_bool(0.2) {
                    let len = rng.gen_range(1..=256);
                    let mut data = vec![0u8; len];
                    rng.fill(&mut data[..]);
                    Some(data)
                } else {
                    None
                };
                
                transfers.push(TransferSketch {
                    amount,
                    asset,
                    destination_pub: dest_pub,
                    extra_data: extra_data.clone(),
                });
                
                println!("  [{}] {} units of asset {}... to {}...", 
                    i,
                    amount,
                    hex::encode(&asset[..8]),
                    hex::encode(&dest_pub[..8])
                );
                if extra_data.is_some() {
                    println!("       (with {} bytes extra data)", extra_data.unwrap().len());
                }
            }
            transfers
        }
        2 => {
            // Burn flow
            println!("\nGenerating burn transaction...");
            let mut rng = thread_rng();
            
            // Random amount to burn
            let amount = rng.gen_range(1000..=10_000_000);
            
            // Random asset
            let asset = if rng.gen_bool(0.5) {
                [0u8; 32] // 50% chance of native asset
            } else {
                generate_random_asset()
            };
            
            // For burns, we still need a "destination" in the TransferSketch
            // but it won't be used in the actual burn transaction
            let (_, dummy_dest) = generate_random_keypair();
            
            println!("  Burning {} units of asset {}...", 
                amount,
                hex::encode(&asset[..8])
            );
            
            vec![TransferSketch {
                amount,
                asset,
                destination_pub: dummy_dest,
                extra_data: None,
            }]
        }
        _ => unreachable!(),
    };

    // Random fee and nonce
    let mut rng = thread_rng();
    let fee = rng.gen_range(100..=10_000);
    let nonce = rng.gen_range(1..=1_000_000);
    
    // Random reference
    let mut ref_hash = [0u8; 32];
    rng.fill(&mut ref_hash);
    let reference = Reference { 
        hash: ref_hash, 
        topoheight: rng.gen_range(1..=1_000_000) 
    };

    println!("\nTransaction parameters:");
    println!("  Fee: {}", fee);
    println!("  Nonce: {}", nonce);
    println!("  Reference: {}... @ height {}", hex::encode(&reference.hash[..8]), reference.topoheight);

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Build a TxSkeleton (commitments + BP transcript input)
    // ─────────────────────────────────────────────────────────────────────────
    let mut skel = build_tx_skeleton_host(&transfers, fee, nonce, source_pubkey, reference);

    println!("\nBuilt TxSkeleton:");
    println!("  outputs: {}", skel.data_transfers.len());
    println!("  range_proof bytes: {}", skel.range_proof.len());
    println!("  fee: {}, nonce: {}", skel.fee, skel.nonce);

    // ─────────────────────────────────────────────────────────────────────────
    // [LEDGER (verifier-style) CHECKS, but performed here on HOST]
    // ─────────────────────────────────────────────────────────────────────────
    let amounts: Vec<u64> = transfers.iter().map(|t| t.amount).collect();
    let commitments: Vec<[u8; 32]> = skel.data_transfers.iter().map(|t| t.commitment).collect();

    let ok = verify_outputs_match_commitments(&skel, &amounts);
    println!("[DEVICE-STYLE] commitment check (host-sim): {}", ok);

    let rp_ok = verify_range_proof_bytes(&skel.range_proof, &commitments);
    println!("[HOST-DEV] range proof verifies: {}", rp_ok);

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Build per-output Ciphertext-Validity proofs (CT proofs)
    // ─────────────────────────────────────────────────────────────────────────
    let ct_objs = match build_ct_validity_proofs(&skel, &amounts) {
        Ok(v) => v,
        Err(e) => { eprintln!("CT proof build failed: {e}"); return; }
    };

    if let Err(e) = fill_ct_validity_proofs(&mut skel, &amounts) {
        eprintln!("CT proof fill failed: {e}");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Generate digest
    // ─────────────────────────────────────────────────────────────────────────
    let digest = digest_for_signing_demo(&skel);
    println!("Digest for signing (SHA512): {}", hex::encode(digest));

    // ─────────────────────────────────────────────────────────────────────────
    // [HOST] Canonical serialization and output
    // ─────────────────────────────────────────────────────────────────────────
    use debugger::canonical::verify_commitments_with_sketches;
    match canonical_roundtrip_bytes_with_ct_verbose(&skel, ct_objs) {
        Ok((unsigned_bytes, tx_bytes)) => {
            // Build preview memo
            let memo = build_preview_memo(&skel, &transfers);

            verify_commitments_with_sketches(&skel, &transfers);

            // Determine output filename based on tx type
            let tx_type_str = match tx_type {
                1 => "transfer",
                2 => "burn",
                _ => "unknown",
            };
            
            let unsigned_bundle = format!("out/poc_{}.unsigned.bundle", tx_type_str);
            let tx_bundle = format!("out/poc_{}.transaction.bundle", tx_type_str);
            
            // Write XLB1 bundles
            write_bundle(&unsigned_bundle, &memo, &unsigned_bytes, &skel.output_blinders);
            write_bundle(&tx_bundle, &memo, &tx_bytes, &skel.output_blinders);
            
            println!("\n✅ Successfully generated {} transaction!", tx_type_str);
            println!("   Unsigned bundle: {}", unsigned_bundle);
            println!("   Transaction bundle: {}", tx_bundle);
        }
        Err(e) => eprintln!("Canonical round-trip (verbose): {e:#}"),
    }
}