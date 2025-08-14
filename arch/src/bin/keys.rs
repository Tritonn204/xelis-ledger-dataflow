use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, Scalar};
use bulletproofs::PedersenGens;
use xelis_common::crypto::{PublicKey as XelisPublicKey, Address, AddressType};
use xelis_common::serializer::Serializer;

fn test_point_validity(name: &str, bytes: &[u8; 32]) {
    println!("\n{} - Testing bytes: {}", name, hex::encode(bytes));
    
    // Try to decompress the point
    let compressed = CompressedRistretto::from_slice(bytes);
    match compressed.expect("INVALID").decompress() {
        Some(point) => {
            println!("✓ Valid compressed point - decompression successful");
            
            // Re-compress and verify we get the same bytes
            let recompressed = point.compress();
            if recompressed.as_bytes() == bytes {
                println!("✓ Re-compression matches original bytes");
            } else {
                println!("✗ Re-compression DOES NOT match!");
                println!("  Original:     {}", hex::encode(bytes));
                println!("  Recompressed: {}", hex::encode(recompressed.as_bytes()));
            }
            
            // Try to create Xelis address
            match XelisPublicKey::from_bytes(bytes) {
                Ok(xelis_pubkey) => {
                    println!("✓ Valid Xelis public key");
                    let addr = Address::new(true, AddressType::Normal, xelis_pubkey);
                    println!("  Mainnet address: {}", addr.to_string());
                },
                Err(e) => {
                    println!("✗ Failed to create Xelis public key: {:?}", e);
                }
            }
        },
        None => {
            println!("✗ INVALID compressed point - decompression failed!");
        }
    }
}

fn main() {
    println!("=== Testing Point Validity ===");
    
    // Test the basepoint/generator you mentioned
    let generator_bytes = hex::decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
        .unwrap()
        .try_into()
        .unwrap();
    test_point_validity("Ristretto Generator", &generator_bytes);
    
    // Test identity point
    let identity_bytes = [0u8; 32];
    test_point_validity("Identity Point", &identity_bytes);
    
    // Test invalid point (your test data)
    let invalid_bytes: [u8; 32] = hex::decode("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
        .unwrap()
        .try_into()
        .unwrap();
    test_point_validity("Test Invalid Point", &invalid_bytes);
    
    println!("\n=== Testing Generated Points ===");
    
    let pc_gens = PedersenGens::default();
    let h = pc_gens.B_blinding;
    
    // Test 1: Private key = 1
    let private_1 = Scalar::ONE;
    let public_1 = private_1.invert() * h;
    let compressed_1 = public_1.compress();
    println!("KEY: {:?}", compressed_1.to_bytes());
    test_point_validity("Private key = 1", compressed_1.as_bytes());
    
    // Test 2: Private key = 2
    let private_2 = Scalar::from(2u64);
    let public_2 = private_2.invert() * h;
    let compressed_2 = public_2.compress();
    println!("KEY: {:?}", compressed_2.to_bytes());
    test_point_validity("Private key = 2", compressed_2.as_bytes());
    
    // Test 3: Private key = [0xff; 32]
    let bytes = [0xffu8; 32];
    let private_3 = Scalar::from_bytes_mod_order(bytes);
    let public_3 = private_3.invert() * h;
    let compressed_3 = public_3.compress();
    println!("KEY: {:?}", compressed_3.to_bytes());
    test_point_validity("Private key = [0xff; 32]", compressed_3.as_bytes());
    
    // Test some known valid Ristretto points
    println!("\n=== Testing Known Valid Points ===");
    
    // These are from the Ristretto test vectors
    let test_vectors = [
        "0000000000000000000000000000000000000000000000000000000000000000", // Identity
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76", // Generator
        "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919", // Another valid point
    ];
    
    for hex_str in &test_vectors {
        let bytes: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
        test_point_validity(&format!("Test vector: {}...", &hex_str[..16]), &bytes);
    }
}