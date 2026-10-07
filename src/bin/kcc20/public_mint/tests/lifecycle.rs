use kaspa_txscript::{opcodes::codes::OpCheckSig, script_builder::ScriptBuilder};
use secp256k1::Keypair;

use super::*;

fn pay_to_pub_key_script(public_key: &[u8; 32]) -> ScriptPublicKey {
    let script = ScriptBuilder::new()
        .add_data(public_key)
        .unwrap()
        .add_op(OpCheckSig)
        .unwrap()
        .drain();
    ScriptPublicKey::from_vec(0, script)
}

fn owner_call(name: &str, key: Keypair) -> EntryCall<'static> {
    EntryCall::new(name).args_with(move |tx, index| args!(sign_input(tx, index, &key)))
}

fn launch(builder: &TxBuilder<'_>) -> (CovenantOutput, CovenantOutput) {
    let owner = demo_keys(0xaa).1;
    let tx = builder
        .build(
            &TxContext::new()
                .input(demo_outpoint(1, 0), funding(), Vec::new(), 0)
                .actor_genesis_output(
                    0,
                    "launch::token",
                    "PublicMint",
                    minter_state(25, 10, &owner, &[0; 32]),
                    TOKEN_OUTPUT_SOMPI,
                )
                .actor_genesis_output(
                    0,
                    "launch::token",
                    "TokenSeed",
                    seeder_state(&owner, &[0; 32]),
                    TOKEN_OUTPUT_SOMPI,
                ),
        )
        .unwrap();
    let minter = CovenantOutput::from_tx(&tx, 0).unwrap();
    let seeder = CovenantOutput::from_tx(&tx, 1).unwrap();
    assert_eq!(minter.covenant_id, seeder.covenant_id);
    (minter, seeder)
}

#[test]
fn minter_split_mint_and_reclaim_return_unused_allowance() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (_, alice_public_key) = demo_keys(0xaa);
    let (bob, bob_public_key) = demo_keys(0xbb);
    let (minter, _) = launch(&builder);
    let binding = CovenantBinding::new(0, minter.covenant_id);
    let added_value = 321;
    let split = |take| {
        builder.build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    minter_state(25, 10, &alice_public_key, &[0; 32]),
                    EntryCall::new("split").args(args!(take, bob_public_key.to_vec())),
                    minter.outpoint,
                    minter.utxo.clone(),
                    0,
                )
                .input(demo_outpoint(2, 0), funding(), Vec::new(), 0)
                .actor_output(
                    "PublicMint",
                    minter_state(25 - take, 10, &alice_public_key, &[0; 32]),
                    binding,
                    TOKEN_OUTPUT_SOMPI,
                )
                .actor_output(
                    "PublicMint",
                    minter_state(take, 10, &bob_public_key, &[0; 32]),
                    binding,
                    added_value,
                ),
        )
    };
    rejects(split(13));
    let split = split(7).unwrap();
    let original = CovenantOutput::from_tx(&split, 0).unwrap();
    let added = CovenantOutput::from_tx(&split, 1).unwrap();

    let minted = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    minter_state(7, 10, &bob_public_key, &[0; 32]),
                    EntryCall::new("mint").args(args!(recipient_state(3))),
                    added.outpoint,
                    added.utxo,
                    0,
                )
                .input(demo_outpoint(3, 0), funding(), Vec::new(), 0)
                .actor_output(
                    "PublicMint",
                    minter_state(4, 10, &bob_public_key, &[0; 32]),
                    binding,
                    added_value,
                )
                .actor_output("KCC20", recipient_state(3), binding, TOKEN_OUTPUT_SOMPI),
        )
        .unwrap();
    let retiring = CovenantOutput::from_tx(&minted, 0).unwrap();
    let reclaimed = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    minter_state(18, 10, &alice_public_key, &[0; 32]),
                    EntryCall::new("reclaim_into"),
                    original.outpoint,
                    original.utxo,
                    0,
                )
                .actor_input(
                    "PublicMint",
                    minter_state(4, 10, &bob_public_key, &[0; 32]),
                    owner_call("reclaim_delegator", bob),
                    retiring.outpoint,
                    retiring.utxo,
                    0,
                )
                .actor_output(
                    "PublicMint",
                    minter_state(22, 10, &alice_public_key, &[0; 32]),
                    binding,
                    TOKEN_OUTPUT_SOMPI,
                )
                .output(pay_to_pub_key_script(&bob_public_key), None, added_value),
        )
        .unwrap();
    assert_eq!(reclaimed.outputs[1].value, added_value);
    assert!(reclaimed.outputs[1].covenant.is_none());
}

#[test]
fn minter_reclaim_requires_exhaustion_and_its_owner() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (alice, alice_public_key) = demo_keys(0xaa);
    let (bob, _) = demo_keys(0xbb);
    let covenant_id = Hash::from_bytes([0x11; 32]);
    let reclaim = |remaining, signer| {
        let state = minter_state(remaining, 10, &alice_public_key, &[0; 32]);
        let utxo = builder
            .covenant_utxo(
                "PublicMint",
                state.clone(),
                TOKEN_OUTPUT_SOMPI,
                1,
                false,
                Some(covenant_id),
            )
            .unwrap();
        builder.build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    state,
                    owner_call("reclaim", signer),
                    demo_outpoint(1, 0),
                    utxo,
                    0,
                )
                .output(
                    pay_to_pub_key_script(&alice_public_key),
                    None,
                    TOKEN_OUTPUT_SOMPI,
                ),
        )
    };
    reclaim(0, alice).unwrap();
    rejects(reclaim(1, alice));
    rejects(reclaim(0, bob));
}

#[test]
fn seeder_split_create_borrow_and_reclaim_keep_a_live_seed() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (alice, alice_public_key) = demo_keys(0xaa);
    let (bob, bob_public_key) = demo_keys(0xbb);
    let (minter, seeder) = launch(&builder);
    let binding = CovenantBinding::new(0, seeder.covenant_id);
    let added_value = 321;
    let split = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "TokenSeed",
                    seeder_state(&alice_public_key, &[0; 32]),
                    EntryCall::new("split").args(args!(bob_public_key.to_vec())),
                    seeder.outpoint,
                    seeder.utxo,
                    0,
                )
                .input(demo_outpoint(2, 0), funding(), Vec::new(), 0)
                .actor_output(
                    "TokenSeed",
                    seeder_state(&alice_public_key, &[0; 32]),
                    binding,
                    TOKEN_OUTPUT_SOMPI,
                )
                .actor_output(
                    "TokenSeed",
                    seeder_state(&bob_public_key, &[0; 32]),
                    binding,
                    added_value,
                ),
        )
        .unwrap();
    let original = CovenantOutput::from_tx(&split, 0).unwrap();
    let added = CovenantOutput::from_tx(&split, 1).unwrap();
    let create = |amount| {
        let recipient = threshold_token_state(&bob_public_key, amount, 0);
        builder.build(
            &TxContext::new()
                .actor_input(
                    "TokenSeed",
                    seeder_state(&bob_public_key, &[0; 32]),
                    EntryCall::new("create").args(args!(recipient.clone())),
                    added.outpoint,
                    added.utxo.clone(),
                    0,
                )
                .input(demo_outpoint(3, 0), funding(), Vec::new(), 0)
                .actor_output(
                    "TokenSeed",
                    seeder_state(&bob_public_key, &[0; 32]),
                    binding,
                    added_value,
                )
                .actor_output("KCC20", recipient, binding, TOKEN_OUTPUT_SOMPI),
        )
    };
    rejects(create(1));
    let created = create(0).unwrap();
    let empty = threshold_token_state(&bob_public_key, 0, 0);
    let retiring = CovenantOutput::from_tx(&created, 0).unwrap();
    let receiver = CovenantOutput::from_tx(&created, 1).unwrap();

    let minted = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    minter_state(25, 10, &alice_public_key, &[0; 32]),
                    EntryCall::new("mint").args(args!(recipient_state(5))),
                    minter.outpoint,
                    minter.utxo,
                    0,
                )
                .input(demo_outpoint(4, 0), funding(), Vec::new(), 0)
                .actor_output(
                    "PublicMint",
                    minter_state(20, 10, &alice_public_key, &[0; 32]),
                    binding,
                    TOKEN_OUTPUT_SOMPI,
                )
                .actor_output("KCC20", recipient_state(5), binding, TOKEN_OUTPUT_SOMPI),
        )
        .unwrap();
    let sender = CovenantOutput::from_tx(&minted, 1).unwrap();
    let received = threshold_token_state(&bob_public_key, 5, 0);
    let paid = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "KCC20",
                    empty,
                    EntryCall::new("transfer")
                        .args(args!(vec![received.clone()], vec![PATH_BORROW])),
                    receiver.outpoint,
                    receiver.utxo,
                    0,
                )
                .actor_input(
                    "KCC20",
                    recipient_state(5),
                    owner_call("transfer_delegator", alice),
                    sender.outpoint,
                    sender.utxo,
                    0,
                )
                .actor_output("KCC20", received, binding, TOKEN_OUTPUT_SOMPI)
                // The sender recovers its own carrier KAS; Bob's deposit funds the destination.
                .output(
                    pay_to_pub_key_script(&alice_public_key),
                    None,
                    TOKEN_OUTPUT_SOMPI,
                ),
        )
        .unwrap();
    assert_eq!(paid.outputs[0].value, TOKEN_OUTPUT_SOMPI);
    assert_eq!(paid.outputs[1].value, TOKEN_OUTPUT_SOMPI);

    let reclaimed = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "TokenSeed",
                    seeder_state(&alice_public_key, &[0; 32]),
                    EntryCall::new("reclaim"),
                    original.outpoint,
                    original.utxo,
                    0,
                )
                .actor_input(
                    "TokenSeed",
                    seeder_state(&bob_public_key, &[0; 32]),
                    owner_call("reclaim_delegator", bob),
                    retiring.outpoint,
                    retiring.utxo.clone(),
                    0,
                )
                .actor_output(
                    "TokenSeed",
                    seeder_state(&alice_public_key, &[0; 32]),
                    binding,
                    TOKEN_OUTPUT_SOMPI,
                )
                .output(pay_to_pub_key_script(&bob_public_key), None, added_value),
        )
        .unwrap();
    assert_eq!(reclaimed.outputs[1].value, added_value);

    // The retiring seed cannot reclaim itself without a surviving leader.
    let mut missing_survivor = reclaimed;
    missing_survivor.inputs.remove(0);
    rejects(execute_transaction_with_covenants(
        &mut missing_survivor,
        vec![retiring.utxo],
    ));
}
