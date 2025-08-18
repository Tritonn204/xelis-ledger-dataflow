use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxGeneratorPayload {
    Transfers(Vec<TransferSketch>),
    Burn { amount: u64, asset: [u8; 32] },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TransferSketch {
    pub amount: u64,
    pub asset: [u8; 32],
    pub destination_pub: [u8; 32],
    pub extra_data: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CtValidityProof {
    pub Y_0: [u8; 32],
    pub Y_1: [u8; 32],
    pub z_r: [u8; 32],
    pub z_x: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SourceCommitmentProof {
    pub Y_0: [u8; 32],
    pub Y_1: [u8; 32],
    pub Y_2: [u8; 32],
    pub z_r: [u8; 32],
    pub z_s: [u8; 32],
    pub z_x: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TransferCommit {
    pub asset: [u8; 32],
    pub commitment: [u8; 32],             // Pedersen commitment (compressed Ristretto)
    pub ct_validity_proof: CtValidityProof,
    pub destination: [u8; 32],            // receiver key/handle
    pub extra_data: Option<Vec<u8>>,
    pub receiver_handle: [u8; 32],
    pub sender_handle: [u8; 32],
    pub ct_validity_proof_bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Reference { pub hash: [u8; 32], pub topoheight: u64 }

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SourceCommitment {
    pub asset: [u8; 32],
    pub commitment: [u8; 32],
    pub proof: SourceCommitmentProof,
    pub eq_proof_bytes: Vec<u8>,    
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxSkeleton {
    pub data_transfers: Vec<TransferCommit>,
    pub range_proof: Vec<u8>,             // Bulletproof(s) bytes
    pub source_commitments: Vec<SourceCommitment>, // per-asset
    pub fee: u64,
    pub nonce: u64,
    pub source: [u8; 32],                 // sender public key
    pub reference: Reference,

    // Not on-chain; only used by “Ledger” checks
    pub output_blinders: Vec<[u8; 32]>,   // Scalar bytes per transfer
    pub tx_type: TxGeneratorPayload,
}