use argent_runtime::{BuilderError, BuilderResult, execute_transaction_with_covenants};
use kaspa_consensus_core::tx::Transaction;

use super::*;

mod lifecycle;

fn artifact() -> &'static Artifact {
    super::super::tests::artifact()
}

fn recipient_state(amount: i64) -> TokenState {
    token_state(&demo_keys(0xaa).1, amount)
}

fn mint_case(
    remaining: i64,
    lot: i64,
    recipient: TokenState,
) -> BuilderResult<(Transaction, Vec<UtxoEntry>)> {
    mint_case_with_extension(remaining, lot, &[0u8; 32], recipient)
}

fn mint_case_with_extension(
    remaining: i64,
    lot: i64,
    extension_commitment: &[u8; 32],
    recipient: TokenState,
) -> BuilderResult<(Transaction, Vec<UtxoEntry>)> {
    let builder = TxBuilder::new(artifact())?;
    let covenant_id = Hash::from_bytes([0x11; 32]);
    let before = minter_state(remaining, lot, &demo_keys(0xaa).1, extension_commitment);
    let ArtifactValue::Int(amount) = recipient["amount"] else {
        panic!("recipient amount must be an integer");
    };
    let utxo = builder.covenant_utxo(
        "PublicMint",
        before.clone(),
        TOKEN_OUTPUT_SOMPI,
        1,
        false,
        Some(covenant_id),
    )?;
    let utxos = vec![utxo.clone(), funding()];
    let transaction = builder.build(
        &TxContext::new()
            .actor_input(
                "PublicMint",
                before,
                EntryCall::new("mint").args(args!(recipient.clone())),
                demo_outpoint(1, 0),
                utxo,
                0,
            )
            .input(demo_outpoint(2, 0), funding(), Vec::new(), 0)
            .actor_output(
                "PublicMint",
                minter_state(
                    remaining - amount,
                    lot,
                    &demo_keys(0xaa).1,
                    extension_commitment,
                ),
                CovenantBinding::new(0, covenant_id),
                TOKEN_OUTPUT_SOMPI,
            )
            .actor_output(
                "KCC20",
                recipient,
                CovenantBinding::new(0, covenant_id),
                TOKEN_OUTPUT_SOMPI,
            ),
    )?;
    Ok((transaction, utxos))
}

fn rejects(result: BuilderResult<impl Sized>) {
    match result {
        Err(BuilderError::InputScript { .. }) => {}
        Err(error) => panic!("expected mint script rejection, got {error:?}"),
        Ok(_) => panic!("invalid mint accepted"),
    }
}

#[test]
fn launch_mint_and_transfer_actual_outputs() {
    run(artifact()).unwrap();
}

#[test]
fn public_mint_accepts_full_partial_and_maximum_allotments() {
    for (remaining, lot) in [
        (25, 10),
        (10, 10),
        (5, 10),
        (i64::MAX, 1),
        (i64::MAX, i64::MAX),
    ] {
        mint_case(remaining, lot, recipient_state(remaining.min(lot))).unwrap();
    }
    for (remaining, lot, amount) in [(25, 10, 3), (25, 10, 9), (5, 10, 4)] {
        mint_case(remaining, lot, recipient_state(amount)).unwrap();
    }
}

#[test]
fn public_mint_rejects_exhaustion_invalid_allowances_and_owner_schemes() {
    for (remaining, lot) in [(0, 10), (-1, 10), (25, 0), (25, -1)] {
        rejects(mint_case(
            remaining,
            lot,
            recipient_state(remaining.min(lot)),
        ));
    }
    let mut recipient = recipient_state(10);
    recipient.insert("owner_scheme".into(), 5u8.into());
    rejects(mint_case(25, 10, recipient));
}

#[test]
fn public_mint_accepts_each_owner_and_borrow_policy() {
    for owner_scheme in 0u8..=4 {
        for borrow_scheme in 0u8..=3 {
            let mut recipient = recipient_state(10);
            recipient.insert("owner_scheme".into(), owner_scheme.into());
            recipient.insert("borrow_scheme".into(), borrow_scheme.into());
            let mut guard = demo_keys(0xcc).1;
            if borrow_scheme == BORROW_AMOUNT_THRESHOLD {
                guard[..8].copy_from_slice(&10i64.to_le_bytes());
            }
            recipient.insert("borrow_guard".into(), guard.to_vec().into());
            mint_case(25, 10, recipient).unwrap();
        }
    }
}

#[test]
fn public_mint_rejects_invalid_recipient_amounts_and_policies() {
    for amount in [-1, 0, 11, 26] {
        rejects(mint_case(25, 10, recipient_state(amount)));
    }
    for amount in [6, 10] {
        rejects(mint_case(5, 10, recipient_state(amount)));
    }

    let mut recipient = recipient_state(10);
    recipient.insert("borrow_scheme".into(), 4u8.into());
    rejects(mint_case(25, 10, recipient));
}

#[test]
fn public_mint_accepts_caller_selected_guard() {
    let mut recipient = recipient_state(10);
    recipient.insert("borrow_scheme".into(), BORROW_AMOUNT_THRESHOLD.into());
    let mut guard = vec![0u8; 32];
    // KCC1 encodes -1 as an eight-byte signed-magnitude payload.
    guard[0] = 1;
    guard[7] = 0x80;
    recipient.insert("borrow_guard".into(), guard.into());
    mint_case(25, 10, recipient).unwrap();
}

#[test]
fn public_mint_requires_configured_extension_commitment() {
    for extension_commitment in [[0u8; 32], [1u8; 32], [0xffu8; 32]] {
        let mut recipient = recipient_state(10);
        recipient.insert(
            "extension_commitment".into(),
            extension_commitment.to_vec().into(),
        );
        mint_case_with_extension(25, 10, &extension_commitment, recipient.clone()).unwrap();

        let mut different = extension_commitment;
        different[31] ^= 1;
        recipient.insert("extension_commitment".into(), different.to_vec().into());
        rejects(mint_case_with_extension(
            25,
            10,
            &extension_commitment,
            recipient,
        ));
    }
}

#[test]
fn mint_binds_allowance_policy_and_recipient_state() {
    let builder = TxBuilder::new(artifact()).unwrap();
    let (_, owner) = demo_keys(0xaa);
    let cases: [(usize, &str, &str, ArtifactValue); 9] = [
        (0, "PublicMint", "remaining", 16i64.into()),
        (0, "PublicMint", "mint_amount", 11i64.into()),
        (
            0,
            "PublicMint",
            "extension_commitment",
            vec![1u8; 32].into(),
        ),
        (1, "KCC20", "amount", 11i64.into()),
        (1, "KCC20", "owner", vec![0xbbu8; 32].into()),
        (1, "KCC20", "owner_scheme", 1u8.into()),
        (1, "KCC20", "borrow_scheme", 1u8.into()),
        (1, "KCC20", "borrow_guard", vec![1u8; 32].into()),
        (1, "KCC20", "extension_commitment", vec![1u8; 32].into()),
    ];
    for (index, actor, field, value) in cases {
        let (mut tx, utxos) = mint_case(25, 10, recipient_state(10)).unwrap();
        let mut state = if index == 0 {
            minter_state(15, 10, &owner, &[0u8; 32])
        } else {
            token_state(&owner, 10)
        };
        state.insert(field.into(), value);
        tx.outputs[index].script_public_key = builder
            .genesis_output(actor, state, TOKEN_OUTPUT_SOMPI)
            .unwrap()
            .script_public_key;
        // Mutate the constructed transaction so rejection comes from the VM.
        rejects(execute_transaction_with_covenants(&mut tx, utxos));
    }
}

#[test]
fn mint_rejects_drained_principal_and_wrong_covenant() {
    let (mut tx, utxos) = mint_case(25, 10, recipient_state(10)).unwrap();
    tx.outputs[0].value -= 1;
    rejects(execute_transaction_with_covenants(&mut tx, utxos));

    let (mut tx, utxos) = mint_case(25, 10, recipient_state(10)).unwrap();
    tx.outputs[1].covenant = Some(CovenantBinding::new(0, Hash::from_bytes([0x22; 32])));
    // The covenant binding is rejected before script execution.
    assert!(matches!(
        execute_transaction_with_covenants(&mut tx, utxos),
        Err(BuilderError::TxScript(_))
    ));
}

#[test]
fn mint_rejects_missing_or_extra_outputs_and_multiple_minters() {
    let (mut tx, utxos) = mint_case(25, 10, recipient_state(10)).unwrap();
    tx.outputs.swap(0, 1);
    rejects(execute_transaction_with_covenants(&mut tx, utxos));

    for index in 0..2 {
        let (mut tx, utxos) = mint_case(25, 10, recipient_state(10)).unwrap();
        tx.outputs.remove(index);
        rejects(execute_transaction_with_covenants(&mut tx, utxos));

        let (mut tx, utxos) = mint_case(25, 10, recipient_state(10)).unwrap();
        tx.outputs.push(tx.outputs[index].clone());
        rejects(execute_transaction_with_covenants(&mut tx, utxos));
    }
    let (mut tx, mut utxos) = mint_case(25, 10, recipient_state(10)).unwrap();
    let mut second = tx.inputs[0].clone();
    second.previous_outpoint = demo_outpoint(3, 0);
    tx.inputs.push(second);
    utxos.push(utxos[0].clone());
    rejects(execute_transaction_with_covenants(&mut tx, utxos));
}
