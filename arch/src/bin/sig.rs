use anyhow::{anyhow, Context, Result};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha3::{Digest, Sha3_512};
use std::{fs, path::Path};

// ---- native Xelis types ----
use xelis_common::crypto::elgamal::{
    Signature as XSignature,
    CompressedPublicKey,
    PublicKey,
};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;

fn print_le_be(label: &str, b: &[u8; 32]) {
    // LE (as provided)
    println!("{} (LE) hex  = {}", label, hex::encode(b));
    print!("{} (LE) array= [", label);
    for (i, byte) in b.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("0x{:02x}", byte);
    }
    println!("]");

    // BE (reversed)
    let mut be = *b;
    be.reverse();
    println!("{} (BE) hex  = {}", label, hex::encode(be));
    print!("{} (BE) array= [", label);
    for (i, byte) in be.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("0x{:02x}", byte);
    }
    println!("]");
    println!();
}

fn dump_generators_from_deps() {
    // G (compressed) from dalek
    let g_comp = RISTRETTO_BASEPOINT_COMPRESSED;
    let g_bytes = g_comp.as_bytes();
    print_le_be("G_compressed (dalek)", g_bytes);

    // H = hash_from_bytes::<Sha3_512>(G_compressed).compress()
    let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(g_bytes);
    let h_comp = h_point.compress();
    let h_bytes = h_comp.as_bytes();
    print_le_be("H_compressed (hash(G))", h_bytes);
}

// ---------- attestation types ----------
#[derive(serde::Deserialize)]
struct SignatureFields {
    // On-wire scalars are little-endian; accept legacy/new field names
    #[serde(alias = "s_le_hex", alias = "s_hex")]
    s_hex: String,
    #[serde(alias = "e_le_hex", alias = "e_hex")]
    e_hex: String,
}

#[derive(serde::Deserialize)]
struct Attestation {
    // Canonical, decompressible Ristretto compressed public key (A)
    device_pubkey_hex: String,
    // Full 64B SHA3-512(tx); if present we assert it matches bundle
    #[serde(default)]
    tx_sha3_512_hex: Option<String>,
    signature: SignatureFields,
}

/* Canonical-compressed H (Pedersen blinding generator) used by XELIS */
const H_HEX: &str = "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";

// ---------- helpers ----------
fn hex_n<const N: usize>(s: &str, name: &str) -> Result<[u8; N]> {
    let v = hex::decode(s).with_context(|| format!("bad hex in {name}"))?;
    if v.len() != N { return Err(anyhow!("{name}: expected {N} bytes, got {}", v.len())); }
    let mut out = [0u8; N]; out.copy_from_slice(&v); Ok(out)
}

fn read_xlb1(path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    fn leb(buf: &[u8], mut off: usize) -> Result<(u64, usize)> {
        let (mut val, mut sft) = (0u64, 0u32);
        loop {
            if off >= buf.len() { return Err(anyhow!("truncated leb128")); }
            let b = buf[off]; off += 1;
            val |= u64::from(b & 0x7F) << sft;
            if (b & 0x80) == 0 { break; }
            sft += 7; if sft > 63 { return Err(anyhow!("leb128 overflow")); }
        }
        Ok((val, off))
    }

    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if data.len() < 6 || &data[0..4] != b"XLB1" {
        return Err(anyhow!("not an XLB1 bundle"));
    }
    let ver = data[4];
    let (memo_len, off_after_mlen) = leb(&data, 5)?;
    let memo_end = off_after_mlen + memo_len as usize;
    if memo_end > data.len() { return Err(anyhow!("memo length out of range")); }
    let memo = data[off_after_mlen .. memo_end].to_vec();

    // v≥1 bundles have a blinders section: [leb(blinders_len)] [blinders_bytes]
    let tx_start = if ver >= 1 {
        let (blinders_len, off_after_blen) = leb(&data, memo_end)?;
        let blinders_end = off_after_blen + blinders_len as usize;
        if blinders_end > data.len() { return Err(anyhow!("blinders length out of range")); }
        if blinders_len % 32 != 0 {
            return Err(anyhow!("blinders not multiple of 32 (got {})", blinders_len));
        }
        blinders_end
    } else {
        // (kept for completeness; you probably don’t ship <v1 anymore)
        memo_end
    };

    let tx = data[tx_start ..].to_vec();
    Ok((memo, tx))
}

fn sha3_512_bytes(bytes: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new(); h.update(bytes); h.finalize().into()
}

// Build a xelis_common::PublicKey from the 32B canonical compressed bytes
fn make_xelis_public(pk_can: [u8; 32]) -> Result<PublicKey> {
    let pk = CompressedRistretto(pk_can).decompress().expect("Bad Pub Key");
    Ok(PublicKey::from_point(pk))
}

fn main() -> Result<()> {
    // dump_generators_from_deps();
    // 1) Load tx → msg64
    let bundle_path = Path::new("out/poc_transfer.unsigned.bundle");
    let (_memo, tx) = read_xlb1(bundle_path)?;
    let msg64 = sha3_512_bytes(&tx);
    println!("Loaded TX: {} bytes", tx.len());
    println!("msg64 = {}", hex::encode(msg64));
    println!("msg32 = {}", hex::encode(&msg64[..32]));

    // 2) Load attestation
    let attest_path = Path::new("out/poc_tx.unsigned.attest.json");
    let s = fs::read_to_string(attest_path).context("read attestation")?;
    let att: Attestation = serde_json::from_str(&s).context("parse attestation json")?;

    // 3) If tx hash provided, assert it matches
    if let Some(hx) = &att.tx_sha3_512_hex {
        let want = hex_n::<64>(hx, "tx_sha3_512_hex")?;
        if want != msg64 {
            return Err(anyhow!("tx_sha3_512 mismatch with bundle"));
        }
        println!("✓ sha3-512(tx) matches attestation");
    }

    // 4) Decompress A and H (canonical compressed encodings)
    let pk_can = hex_n::<32>(&att.device_pubkey_hex, "device_pubkey_hex")?;
    let a_point = CompressedRistretto(pk_can)
        .decompress()
        .ok_or_else(|| anyhow!("bad device pubkey"))?;
    println!("✓ device pubkey decompress OK");

    let h_can = hex_n::<32>(H_HEX, "H_HEX")?;
    let h_point = CompressedRistretto(h_can)
        .decompress()
        .ok_or_else(|| anyhow!("bad H constant"))?;

    // 5) Parse signature scalars (LE on-wire → dalek Scalar)
    let s_le = hex_n::<32>(&att.signature.s_hex, "sig.s_hex")?;
    let e_le = hex_n::<32>(&att.signature.e_hex, "sig.e_hex")?;
    let s = Scalar::from_bytes_mod_order(s_le);
    let e = Scalar::from_bytes_mod_order(e_le);

    // 6) Math-only check (Xelis semantics): R' = s·H − e·A; e' = H(A||msg64||R') LE-wide
    let r_prime: RistrettoPoint = s * h_point + (-e) * a_point;
    let r_can = r_prime.compress();

    let mut hh = Sha3_512::new();
    hh.update(&pk_can);                // canonical compressed A (matches native code)
    hh.update(&msg64);
    hh.update(r_can.as_bytes());       // canonical compressed R'
    let digest64: [u8; 64] = hh.finalize().into();
    let e_prime = Scalar::from_bytes_mod_order_wide(&digest64);

    let ok_math = e_prime.to_bytes() == e_le;
    println!("e(LE-wide, canonical-hash) == e_le ? {}", ok_math);
    if !ok_math {
        println!("e' = {}", hex::encode(e_prime.to_bytes()));
        println!("e  = {}", hex::encode(e_le));
        return Err(anyhow!("signature verification failed (e mismatch)"));
    }

    // 7) Native Xelis verify using xelis_common::Signature
    // Build native Signature (its fields are dalek Scalars, same endianness already)
    let sig_native = XSignature::new(s, e);

    // Build native PublicKey
    let key_native = make_xelis_public(pk_can)?; // uncomment the right constructor inside

    let ok_native = sig_native.verify(&msg64, &key_native);
    println!("Native Xelis verify: {}", ok_native);
    if !ok_native {
        return Err(anyhow!("native Xelis verify returned false"));
    }

    println!("✔ Verification OK (math + native).");
    Ok(())
}
