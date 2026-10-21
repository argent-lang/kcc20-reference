//! Deterministic keys and signing for the offline reference example and tests.

use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{MutableTransaction, Transaction, TransactionId, TransactionOutpoint},
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

pub type DemoResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Public, deterministic keys for synthetic UTXOs only.
pub fn demo_keys(seed: u8) -> (Keypair, [u8; 32]) {
    let secret_key = SecretKey::from_slice(&[seed; 32]).expect("valid demo seed");
    let key = Keypair::from_secret_key(&Secp256k1::new(), &secret_key);
    (key, key.x_only_public_key().0.serialize())
}

pub fn demo_outpoint(seed: u8, index: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(TransactionId::from_bytes([seed; 32]), index)
}

/// A 64-byte Schnorr signature followed by SIGHASH_ALL.
pub fn sign_input(
    tx: &MutableTransaction<Transaction>,
    input_index: usize,
    key: &Keypair,
) -> Vec<u8> {
    let digest = calc_schnorr_signature_hash(
        &tx.as_verifiable(),
        input_index,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let mut witness = key
        .sign_schnorr(Message::from_digest(digest.as_bytes()))
        .as_ref()
        .to_vec();
    witness.push(SIG_HASH_ALL.to_u8());
    witness
}
