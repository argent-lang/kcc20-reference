use std::collections::BTreeMap;

use argent::build_file;
use argent_runtime::{ArtifactValue, EntryCall, TxBuilder, TxContext, args, state};
use kaspa_consensus_core::{Hash, tx::CovenantBinding};

mod chain_borrow;
mod public_mint;
mod support;
use support::{DemoResult, demo_keys, demo_outpoint, sign_input};

#[cfg(test)]
mod tests;

const OWNER_P2PK_SCHNORR: u8 = 0x00;
const BORROW_DISABLED: u8 = 0x00;
const BORROW_AMOUNT_THRESHOLD: u8 = 0x01;
const PATH_BORROW: u8 = 0x01;
const TOKEN_OUTPUT_SOMPI: u64 = 1_000;

type TokenState = BTreeMap<String, ArtifactValue>;

fn threshold_token_state(owner: &[u8; 32], amount: i64, threshold: i64) -> TokenState {
    assert!(threshold >= 0, "borrow threshold must be non-negative");
    let mut guard = [0u8; 32];
    // Non-negative KCC1 ScriptNum payloads use eight little-endian bytes.
    guard[..8].copy_from_slice(&threshold.to_le_bytes());
    let mut state = token_state(owner, amount);
    state.insert("borrow_scheme".into(), BORROW_AMOUNT_THRESHOLD.into());
    state.insert("borrow_guard".into(), guard.to_vec().into());
    state
}

fn token_state(owner: &[u8; 32], amount: i64) -> TokenState {
    state! {
        amount: amount,
        owner: owner.to_vec(),
        owner_scheme: OWNER_P2PK_SCHNORR,
        borrow_scheme: BORROW_DISABLED,
        borrow_guard: vec![0u8; 32],
        // An arbitrary shared commitment; zero has no special protocol meaning.
        extension_commitment: vec![0u8; 32]
    }
}

fn main() -> DemoResult<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut arguments = std::env::args().skip(1);
    let example = arguments.next();
    if arguments.next().is_some() {
        return Err("usage: kcc20 [threshold|hash-chain|mint]".into());
    }
    let artifact = build_file(
        root.join("contracts/public_mint.ag"),
        root.join("build/public-mint"),
    )?;
    match example.as_deref() {
        Some("mint") => return public_mint::run(&artifact),
        Some("hash-chain") => return chain_borrow::run(&artifact),
        None | Some("threshold") => {}
        Some(_) => return Err("usage: kcc20 [threshold|hash-chain|mint]".into()),
    }
    let (alice, alice_public_key) = demo_keys(0xaa);
    let (_, bob_public_key) = demo_keys(0xbb);

    let alice_outpoint = demo_outpoint(1, 0);
    let bob_outpoint = demo_outpoint(2, 0);

    // Alice adds 11 tokens to Bob's UTXO, exceeding his threshold of 10.
    let bob_before = threshold_token_state(&bob_public_key, 200, 10);
    let alice_before = token_state(&alice_public_key, 100);

    let bob_after = threshold_token_state(&bob_public_key, 211, 10);
    let alice_after = token_state(&alice_public_key, 89);

    let builder = TxBuilder::new(&artifact)?;

    // Synthetic lineage and outpoints keep this example entirely offline.
    let covenant_id = Hash::from_bytes([0x11; 32]);
    let bob_utxo = builder.covenant_utxo(
        "KCC20",
        bob_before.clone(),
        TOKEN_OUTPUT_SOMPI,
        1,
        false,
        Some(covenant_id),
    )?;
    let alice_utxo = builder.covenant_utxo(
        "KCC20",
        alice_before.clone(),
        TOKEN_OUTPUT_SOMPI,
        1,
        false,
        Some(covenant_id),
    )?;
    let next_states = vec![bob_after.clone(), alice_after.clone()];

    let transfer = EntryCall::new("transfer").args_with(|_tx, _input_index| {
        let witness = vec![PATH_BORROW];
        args!(next_states.clone(), witness)
    });
    let delegate = EntryCall::new("transfer_delegator")
        .args_with(|tx, input_index| args!(sign_input(tx, input_index, &alice)));

    // Bob leads through borrowed receive; Alice authorizes her own delegate input.
    let context = TxContext::new()
        .actor_input("KCC20", bob_before, transfer, bob_outpoint, bob_utxo, 0)
        .actor_input(
            "KCC20",
            alice_before,
            delegate,
            alice_outpoint,
            alice_utxo,
            0,
        )
        .actor_output(
            "KCC20",
            bob_after,
            CovenantBinding::new(0, covenant_id),
            TOKEN_OUTPUT_SOMPI,
        )
        .actor_output(
            "KCC20",
            alice_after,
            CovenantBinding::new(0, covenant_id),
            TOKEN_OUTPUT_SOMPI,
        );

    let transaction = builder.build(&context)?;
    println!("transaction: {}", transaction.id());
    println!("inputs: {}", transaction.inputs.len());
    println!("outputs: {}", transaction.outputs.len());
    Ok(())
}
