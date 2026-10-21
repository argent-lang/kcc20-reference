use argent::{artifact::Artifact, build_file};
use argent_runtime::{
    ArtifactValue, CovenantOutput, EntryCall, TxBuilder, TxContext, args,
    execute_transaction_with_covenants,
};
use kas20::{ActorState, MINTER_VALUE, SOMPI_PER_KAS, backed_value, minter_state, token_state};
use kaspa_consensus_core::{
    Hash,
    tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionOutput, UtxoEntry},
};
use kcc20_reference::demo_support::{demo_keys, demo_outpoint, sign_input};
use std::sync::OnceLock;

fn artifact() -> &'static Artifact {
    static VALUE: OnceLock<Artifact> = OnceLock::new();
    VALUE.get_or_init(|| {
        build_file(
            concat!(env!("CARGO_MANIFEST_DIR"), "/contracts/app.ag"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/build/test-kas20"),
        )
        .unwrap()
    })
}
fn ordinary(value: u64) -> UtxoEntry {
    UtxoEntry::new(
        value,
        ScriptPublicKey::from_vec(0, vec![0x51]),
        1,
        false,
        None,
    )
}
fn binding() -> CovenantBinding {
    CovenantBinding::new(0, Hash::from_bytes([0x11; 32]))
}
fn actor_utxo(builder: &TxBuilder<'_>, actor: &str, state: ActorState, value: u64) -> UtxoEntry {
    builder
        .covenant_utxo(actor, state, value, 1, false, Some(binding().covenant_id))
        .unwrap()
}
fn mint(value: u64, amount: i64) -> argent_runtime::BuilderResult<Transaction> {
    let builder = TxBuilder::new(artifact()).unwrap();
    let owner = demo_keys(0xaa).1;
    let before = minter_state(&owner);
    builder.build(
        &TxContext::new()
            .actor_input(
                "PublicMint",
                before.clone(),
                EntryCall::new("mint").args(args!(token_state(&owner, amount))),
                demo_outpoint(1, 0),
                actor_utxo(&builder, "PublicMint", before, MINTER_VALUE),
                0,
            )
            .input(demo_outpoint(2, 0), ordinary(value), Vec::new(), 0)
            .actor_output("PublicMint", minter_state(&owner), binding(), MINTER_VALUE)
            .actor_output("KAS20", token_state(&owner, amount), binding(), value),
    )
}
#[test]
fn mint_requires_exact_backing_without_an_issuance_cap() {
    let value = backed_value(SOMPI_PER_KAS).unwrap();
    mint(value, SOMPI_PER_KAS).unwrap();
    for bad in [value - 1, value + 1, MINTER_VALUE] {
        assert!(mint(bad, SOMPI_PER_KAS).is_err());
    }
    for amount in [3 * SOMPI_PER_KAS, 100 * SOMPI_PER_KAS, i64::MAX] {
        mint(amount as u64, amount).unwrap();
    }
    assert!(mint(0, -1).is_err());
}
#[test]
fn raw_underfunded_mint_is_rejected_by_vm() {
    let value = backed_value(SOMPI_PER_KAS).unwrap();
    let mut tx = mint(value, SOMPI_PER_KAS).unwrap();
    let builder = TxBuilder::new(artifact()).unwrap();
    let owner = demo_keys(0xaa).1;
    let entry = actor_utxo(&builder, "PublicMint", minter_state(&owner), MINTER_VALUE);
    tx.outputs[1].value -= 1;
    tx.outputs.push(TransactionOutput::new(
        1,
        ScriptPublicKey::from_vec(0, vec![0x51]),
    ));
    assert!(execute_transaction_with_covenants(&mut tx, vec![entry, ordinary(value)]).is_err());
}
fn transfer(outputs: &[i64], values: &[u64]) -> argent_runtime::BuilderResult<Transaction> {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (key, owner) = demo_keys(0xaa);
    let amount = outputs.iter().sum();
    let before = token_state(&owner, amount);
    let states: Vec<_> = outputs.iter().map(|n| token_state(&owner, *n)).collect();
    let args_states = states.clone();
    let mut context = TxContext::new()
        .actor_input(
            "KAS20",
            before.clone(),
            EntryCall::new("transfer").args_with(move |tx, index| {
                let mut witness = vec![0];
                witness.extend(sign_input(tx, index, &key));
                args!(args_states.clone(), witness)
            }),
            demo_outpoint(1, 0),
            actor_utxo(&builder, "KAS20", before, backed_value(amount).unwrap()),
            0,
        )
        .input(
            demo_outpoint(2, 0),
            ordinary((outputs.len().saturating_sub(1) as u64) * MINTER_VALUE),
            Vec::new(),
            0,
        );
    for (state, value) in states.into_iter().zip(values) {
        context = context.actor_output("KAS20", state, binding(), *value);
    }
    builder.build(&context)
}
#[test]
fn split_transfer_requires_backing_on_each_output() {
    let amounts = [40, 60];
    let values = [backed_value(40).unwrap(), backed_value(60).unwrap()];
    transfer(&amounts, &values).unwrap();
    assert!(transfer(&amounts, &[values[0] - 1, values[1] + 1]).is_err());
    assert!(transfer(&amounts, &[values[0] + 1, values[1] - 1]).is_err());
    transfer(
        &[20, 30, 50],
        &[
            backed_value(20).unwrap(),
            backed_value(30).unwrap(),
            backed_value(50).unwrap(),
        ],
    )
    .unwrap();
}
#[test]
fn borrowed_receive_moves_both_tokens_and_backing() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (_, bob) = demo_keys(0xbb);
    let (alice, owner) = demo_keys(0xaa);
    let mut before = token_state(&bob, 100);
    before.insert("borrow_scheme".into(), 1u8.into());
    let mut after = before.clone();
    after.insert("amount".into(), 110i64.into());
    let sender = token_state(&owner, 100);
    let build = |borrowed_value: u64| {
        builder.build(
            &TxContext::new()
                .actor_input(
                    "KAS20",
                    before.clone(),
                    EntryCall::new("transfer").args(args!(
                        vec![after.clone(), token_state(&owner, 90)],
                        vec![1u8]
                    )),
                    demo_outpoint(1, 0),
                    actor_utxo(
                        &builder,
                        "KAS20",
                        before.clone(),
                        backed_value(100).unwrap(),
                    ),
                    0,
                )
                .actor_input(
                    "KAS20",
                    sender.clone(),
                    EntryCall::new("transfer_delegator")
                        .args_with(move |tx, index| args!(sign_input(tx, index, &alice))),
                    demo_outpoint(2, 0),
                    actor_utxo(
                        &builder,
                        "KAS20",
                        sender.clone(),
                        backed_value(100).unwrap(),
                    ),
                    0,
                )
                .actor_output("KAS20", after.clone(), binding(), borrowed_value)
                .actor_output(
                    "KAS20",
                    token_state(&owner, 90),
                    binding(),
                    backed_value(90).unwrap(),
                ),
        )
    };
    build(backed_value(110).unwrap()).unwrap();
    assert!(build(backed_value(100).unwrap()).is_err());
}
fn burn(
    signer: u8,
    payout: u64,
    payout_script: ScriptPublicKey,
) -> argent_runtime::BuilderResult<Transaction> {
    let builder = TxBuilder::new(artifact()).unwrap();
    let owner = demo_keys(0xaa).1;
    let key = demo_keys(signer).0;
    let state = token_state(&owner, SOMPI_PER_KAS);
    let value = backed_value(SOMPI_PER_KAS).unwrap();
    builder.build(
        &TxContext::new()
            .actor_input(
                "KAS20",
                state.clone(),
                EntryCall::new("burn")
                    .args_with(move |tx, index| args!(sign_input(tx, index, &key))),
                demo_outpoint(1, 0),
                actor_utxo(&builder, "KAS20", state, value),
                0,
            )
            .output(payout_script, None, payout),
    )
}
#[test]
fn burn_releases_backing_with_owner_selected_payout_and_fees() {
    let value = backed_value(SOMPI_PER_KAS).unwrap();
    let script = ScriptPublicKey::from_vec(0, vec![0x51]);
    let tx = burn(0xaa, value, script.clone()).unwrap();
    assert!(tx.outputs.iter().all(|o| o.covenant.is_none()));
    assert!(burn(0xbb, value, script.clone()).is_err());
    burn(0xaa, value - 1, script).unwrap();
    burn(0xaa, value, ScriptPublicKey::from_vec(0, vec![0x52])).unwrap();
}
#[test]
fn burn_requires_owner_authorization_without_a_successor() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (key, owner) = demo_keys(0xaa);
    let mut state = token_state(&owner, SOMPI_PER_KAS);
    // Receiving through the borrow path is allowed, but burning still needs the owner.
    state.insert("borrow_scheme".into(), 1u8.into());
    let value = backed_value(SOMPI_PER_KAS).unwrap();
    let build = |authorized, continuation| {
        let mut context = TxContext::new()
            .actor_input(
                "KAS20",
                state.clone(),
                EntryCall::new("burn").args_with(move |tx, index| {
                    let witness = if authorized {
                        sign_input(tx, index, &key)
                    } else {
                        Vec::new()
                    };
                    args!(witness)
                }),
                demo_outpoint(1, 0),
                actor_utxo(&builder, "KAS20", state.clone(), value),
                0,
            )
            .output(ScriptPublicKey::from_vec(0, vec![0x51]), None, value);
        if continuation {
            context = context.actor_output("KAS20", token_state(&owner, 0), binding(), 0);
        }
        builder.build(&context)
    };
    let tx = build(true, false).unwrap();
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, value);
    assert!(tx.outputs[0].covenant.is_none());
    assert!(build(false, false).is_err());
    assert!(build(true, true).is_err());
}
#[test]
fn mint_adds_no_extra_token_deposit() {
    for amount in [1, 2] {
        mint(amount as u64, amount).unwrap();
    }
}
#[test]
fn split_minter_clones_an_uncapped_lane_without_owner_authorization() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (_, alice) = demo_keys(0xaa);
    let (_, bob) = demo_keys(0xbb);
    let before = minter_state(&alice);
    let split = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    before.clone(),
                    EntryCall::new("split").args(args!(bob.to_vec())),
                    demo_outpoint(1, 0),
                    actor_utxo(&builder, "PublicMint", before, MINTER_VALUE),
                    0,
                )
                .input(demo_outpoint(2, 0), ordinary(MINTER_VALUE), Vec::new(), 0)
                .actor_output("PublicMint", minter_state(&alice), binding(), MINTER_VALUE)
                .actor_output("PublicMint", minter_state(&bob), binding(), MINTER_VALUE),
        )
        .unwrap();
    let lane = CovenantOutput::from_tx(&split, 1).unwrap();
    builder
        .build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    minter_state(&bob),
                    EntryCall::new("mint").args(args!(token_state(&alice, 10))),
                    lane.outpoint,
                    lane.utxo,
                    0,
                )
                .input(demo_outpoint(3, 0), ordinary(10), Vec::new(), 0)
                .actor_output("PublicMint", minter_state(&bob), binding(), MINTER_VALUE)
                .actor_output("KAS20", token_state(&alice, 10), binding(), 10),
        )
        .unwrap();
}
fn rebalance_value_preserves_owner_and_requires_authorization(actor: &'static str) {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (alice, owner) = demo_keys(0xaa);
    let (bob, other_owner) = demo_keys(0xbb);
    let state = minter_state(&owner);
    let rebalance = |next_state, value, signer| {
        builder.build(
            &TxContext::new()
                .actor_input(
                    actor,
                    state.clone(),
                    EntryCall::new("rebalance_value")
                        .args_with(move |tx, index| args!(sign_input(tx, index, &signer))),
                    demo_outpoint(1, 0),
                    actor_utxo(&builder, actor, state.clone(), MINTER_VALUE),
                    0,
                )
                .input(demo_outpoint(2, 0), ordinary(MINTER_VALUE), Vec::new(), 0)
                .actor_output(actor, next_state, binding(), value)
                .output(
                    ScriptPublicKey::from_vec(0, vec![0x51]),
                    None,
                    MINTER_VALUE * 2 - value,
                ),
        )
    };
    for value in [1, MINTER_VALUE / 2, MINTER_VALUE, MINTER_VALUE * 2 - 1] {
        let tx = rebalance(state.clone(), value, alice).unwrap();
        assert_eq!(tx.outputs[0].value, value);
        assert_eq!(tx.outputs[1].value, MINTER_VALUE * 2 - value);
        assert!(tx.outputs[1].covenant.is_none());
        assert_eq!(
            CovenantOutput::from_tx(&tx, 0).unwrap().covenant_id,
            binding().covenant_id
        );
    }
    assert!(rebalance(state.clone(), MINTER_VALUE / 2, bob).is_err());
    assert!(rebalance(minter_state(&other_owner), MINTER_VALUE / 2, alice).is_err());
    assert!(
        builder
            .build(
                &TxContext::new()
                    .actor_input(
                        actor,
                        state.clone(),
                        EntryCall::new("rebalance_value")
                            .args_with(move |tx, index| args!(sign_input(tx, index, &alice))),
                        demo_outpoint(1, 0),
                        actor_utxo(&builder, actor, state, MINTER_VALUE),
                        0,
                    )
                    .output(ScriptPublicKey::from_vec(0, vec![0x51]), None, MINTER_VALUE)
            )
            .is_err()
    );
}
#[test]
fn minter_rebalance_value_preserves_owner_and_requires_authorization() {
    rebalance_value_preserves_owner_and_requires_authorization("PublicMint");
}
#[test]
fn retiring_minter_requires_its_owner_and_preserves_a_surviving_lane() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (alice, alice_owner) = demo_keys(0xaa);
    let (bob, bob_owner) = demo_keys(0xbb);
    let survivor = minter_state(&alice_owner);
    let retiring = minter_state(&bob_owner);
    let build = |key| {
        builder.build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    survivor.clone(),
                    EntryCall::new("reclaim"),
                    demo_outpoint(1, 0),
                    actor_utxo(&builder, "PublicMint", survivor.clone(), MINTER_VALUE),
                    0,
                )
                .actor_input(
                    "PublicMint",
                    retiring.clone(),
                    EntryCall::new("reclaim_delegator")
                        .args_with(move |tx, index| args!(sign_input(tx, index, &key))),
                    demo_outpoint(2, 0),
                    actor_utxo(&builder, "PublicMint", retiring.clone(), MINTER_VALUE),
                    0,
                )
                .actor_output("PublicMint", survivor.clone(), binding(), MINTER_VALUE)
                .output(ScriptPublicKey::from_vec(0, vec![0x51]), None, MINTER_VALUE),
        )
    };
    build(bob).unwrap();
    assert!(build(alice).is_err());
    assert!(
        builder
            .build(
                &TxContext::new()
                    .actor_input(
                        "PublicMint",
                        survivor.clone(),
                        EntryCall::new("reclaim"),
                        demo_outpoint(1, 0),
                        actor_utxo(&builder, "PublicMint", survivor, MINTER_VALUE),
                        0
                    )
                    .output(ScriptPublicKey::from_vec(0, vec![0x51]), None, MINTER_VALUE)
            )
            .is_err()
    );
}
#[test]
fn reference_abi_remains_standard_and_added_burning_is_separate() {
    let token = &artifact().sil_abi.contracts["KAS20"];
    assert!(token.entries.contains_key("transfer"));
    assert!(token.entries.contains_key("transfer_delegator"));
    assert!(token.entries.contains_key("burn"));
    assert_eq!(
        token.entries["transfer"].dispatch_tag.as_bytes(),
        &[0x79, 0xc7, 0x1c, 0x23]
    );
    assert_eq!(
        token.entries["transfer_delegator"].dispatch_tag.as_bytes(),
        &[0xfd, 0x3e, 0xf1, 0x4a]
    );
    assert_eq!(token_state(&demo_keys(0xaa).1, 1).len(), 6);
    assert_eq!(artifact().sil_abi.contracts.len(), 2);
    assert_eq!(minter_state(&demo_keys(0xaa).1).len(), 1);
}
#[test]
fn minter_cannot_change_extension_identity() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let owner = demo_keys(0xaa).1;
    let before = minter_state(&owner);
    let mut changed = token_state(&owner, 1);
    changed.insert(
        "extension_commitment".into(),
        ArtifactValue::Bytes(vec![0x42; 32]),
    );
    assert!(
        builder
            .build(
                &TxContext::new()
                    .actor_input(
                        "PublicMint",
                        before.clone(),
                        EntryCall::new("mint").args(args!(changed.clone())),
                        demo_outpoint(1, 0),
                        actor_utxo(&builder, "PublicMint", before, MINTER_VALUE),
                        0
                    )
                    .input(
                        demo_outpoint(2, 0),
                        ordinary(backed_value(1).unwrap()),
                        Vec::new(),
                        0
                    )
                    .actor_output("PublicMint", minter_state(&owner), binding(), MINTER_VALUE)
                    .actor_output("KAS20", changed, binding(), backed_value(1).unwrap())
            )
            .is_err()
    );
}
