//! Two borrowed receives using successive links of the same hash chain.

use argent::artifact::Artifact;
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
use secp256k1::Keypair;

use super::{
    CovenantBinding, DemoResult, EntryCall, Hash, PATH_BORROW, TOKEN_OUTPUT_SOMPI, TxBuilder,
    TxContext, args, demo_keys, demo_outpoint, sign_input, token_state,
};

const BORROW_HASH_CHAIN: u8 = 0x03;

fn commitment(next_guard: [u8; 32], key: &Keypair) -> [u8; 32] {
    let mut preimage = next_guard.to_vec();
    preimage.extend(key.x_only_public_key().0.serialize());
    *blake3::hash(&preimage).as_bytes()
}

pub fn run(artifact: &Artifact) -> DemoResult<()> {
    let builder = TxBuilder::new(artifact)?;
    let (alice, alice_public_key) = demo_keys(0xaa);
    let (_, bob_public_key) = demo_keys(0xbb);
    let (first_key, _) = demo_keys(0xcc);
    let (second_key, _) = demo_keys(0xdd);
    let covenant_id = Hash::from_bytes([0x11; 32]);

    // Construct the chain backwards; release its links in spending order.
    let final_guard = [0x42; 32];
    let middle_guard = commitment(final_guard, &second_key);
    let initial_guard = commitment(middle_guard, &first_key);
    let mut bob_state = token_state(&bob_public_key, 200);
    bob_state.insert("borrow_scheme".into(), BORROW_HASH_CHAIN.into());
    bob_state.insert("borrow_guard".into(), initial_guard.to_vec().into());
    let mut alice_state = token_state(&alice_public_key, 100);
    let mut bob_outpoint = demo_outpoint(1, 0);
    let mut alice_outpoint = demo_outpoint(2, 0);
    let mut bob_utxo = builder.covenant_utxo(
        "KCC20",
        bob_state.clone(),
        TOKEN_OUTPUT_SOMPI,
        1,
        false,
        Some(covenant_id),
    )?;
    let mut alice_utxo = builder.covenant_utxo(
        "KCC20",
        alice_state.clone(),
        TOKEN_OUTPUT_SOMPI,
        1,
        false,
        Some(covenant_id),
    )?;

    println!("initial guard: {}", Hash::from_bytes(initial_guard));
    for (step, (next_guard, borrow_key)) in [(middle_guard, first_key), (final_guard, second_key)]
        .into_iter()
        .enumerate()
    {
        let received = step as i64 + 1;
        let mut bob_after = bob_state.clone();
        bob_after.insert("amount".into(), (200 + received).into());
        bob_after.insert("borrow_guard".into(), next_guard.to_vec().into());
        let alice_after = token_state(&alice_public_key, 100 - received);
        let next_states = vec![bob_after.clone(), alice_after.clone()];
        let borrow = EntryCall::new("transfer").args_with(|transaction, input_index| {
            let mut witness = vec![PATH_BORROW];
            witness.extend(next_guard);
            witness.extend(borrow_key.x_only_public_key().0.serialize());
            witness.extend(sign_input(transaction, input_index, &borrow_key));
            args!(next_states.clone(), witness)
        });
        let delegate =
            EntryCall::new("transfer_delegator").args_with(|transaction, input_index| {
                args!(sign_input(transaction, input_index, &alice))
            });
        let context = TxContext::new()
            .actor_input("KCC20", bob_state, borrow, bob_outpoint, bob_utxo, 0)
            .actor_input(
                "KCC20",
                alice_state,
                delegate,
                alice_outpoint,
                alice_utxo,
                0,
            )
            .actor_output(
                "KCC20",
                bob_after.clone(),
                CovenantBinding::new(0, covenant_id),
                TOKEN_OUTPUT_SOMPI,
            )
            .actor_output(
                "KCC20",
                alice_after.clone(),
                CovenantBinding::new(0, covenant_id),
                TOKEN_OUTPUT_SOMPI,
            );
        let transaction = builder.build(&context)?;
        println!("borrow {}: {}", step + 1, transaction.id());
        println!("  Bob: {}; Alice: {}", 200 + received, 100 - received);
        println!("  successor guard: {}", Hash::from_bytes(next_guard));

        // The next borrow spends the actual outputs of this validated transaction.
        bob_outpoint = TransactionOutpoint::new(transaction.id(), 0);
        alice_outpoint = TransactionOutpoint::new(transaction.id(), 1);
        let successor_utxo = |index: usize| {
            let output = &transaction.outputs[index];
            UtxoEntry::new(
                output.value,
                output.script_public_key.clone(),
                1,
                false,
                Some(covenant_id),
            )
        };
        bob_utxo = successor_utxo(0);
        alice_utxo = successor_utxo(1);
        bob_state = bob_after;
        alice_state = alice_after;
    }
    println!("Chain exhausted: both released links have been consumed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn example_spends_successive_hash_chain_outputs() {
        super::run(super::super::tests::artifact()).unwrap();
    }
}
