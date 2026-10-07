//! Offline launch, public mint, and transfer of the minted tokens.

use argent::artifact::Artifact;
use argent_runtime::CovenantOutput;
use kaspa_consensus_core::tx::{ScriptPublicKey, UtxoEntry};

use super::*;

fn minter_state(
    remaining: i64,
    mint_amount: i64,
    owner: &[u8; 32],
    extension_commitment: &[u8; 32],
) -> TokenState {
    state! {
        remaining: remaining,
        mint_amount: mint_amount,
        owner: owner.to_vec(),
        extension_commitment: extension_commitment.to_vec()
    }
}

fn seeder_state(owner: &[u8; 32], extension_commitment: &[u8; 32]) -> TokenState {
    state! {
        owner: owner.to_vec(),
        extension_commitment: extension_commitment.to_vec()
    }
}

fn funding() -> UtxoEntry {
    // Synthetic OP_TRUE funding keeps the example focused on the actors.
    UtxoEntry::new(
        TOKEN_OUTPUT_SOMPI * 2,
        ScriptPublicKey::from_vec(0, vec![0x51]),
        1,
        false,
        None,
    )
}

pub fn run(artifact: &Artifact) -> DemoResult<()> {
    let builder = TxBuilder::new(artifact)?;
    let (alice, alice_public_key) = demo_keys(0xaa);
    let (_, bob_public_key) = demo_keys(0xbb);
    let mut remaining = 25;
    let lot = 10;
    // This deployment uses zero as its fixed extension identity.
    let extension_commitment = [0u8; 32];
    let launch = builder.build(
        &TxContext::new()
            .input(demo_outpoint(1, 0), funding(), Vec::new(), 0)
            .actor_genesis_output(
                0,
                "launch::token",
                "PublicMint",
                minter_state(remaining, lot, &alice_public_key, &extension_commitment),
                TOKEN_OUTPUT_SOMPI,
            )
            .actor_genesis_output(
                0,
                "launch::token",
                "TokenSeed",
                seeder_state(&alice_public_key, &extension_commitment),
                TOKEN_OUTPUT_SOMPI,
            ),
    )?;
    let mut minter = CovenantOutput::from_tx(&launch, 0)?;
    println!("launch: {}", launch.id());
    println!("covenant: {}", minter.covenant_id);

    for step in 0..3 {
        let amount = remaining.min(lot);
        let mut minted_state = token_state(&alice_public_key, amount);
        minted_state.insert(
            "extension_commitment".into(),
            extension_commitment.to_vec().into(),
        );
        let mint = builder.build(
            &TxContext::new()
                .actor_input(
                    "PublicMint",
                    minter_state(remaining, lot, &alice_public_key, &extension_commitment),
                    EntryCall::new("mint").args(args!(minted_state.clone())),
                    minter.outpoint,
                    minter.utxo,
                    0,
                )
                .input(demo_outpoint(2, step), funding(), Vec::new(), 0)
                .actor_output(
                    "PublicMint",
                    minter_state(
                        remaining - amount,
                        lot,
                        &alice_public_key,
                        &extension_commitment,
                    ),
                    CovenantBinding::new(0, minter.covenant_id),
                    TOKEN_OUTPUT_SOMPI,
                )
                .actor_output(
                    "KCC20",
                    minted_state.clone(),
                    CovenantBinding::new(0, minter.covenant_id),
                    TOKEN_OUTPUT_SOMPI,
                ),
        )?;
        remaining -= amount;
        println!(
            "mint: {} — {amount} tokens, {remaining} remaining",
            mint.id()
        );
        minter = CovenantOutput::from_tx(&mint, 0)?;

        // Spend the actual minted output through the unchanged token actor.
        let token = CovenantOutput::from_tx(&mint, 1)?;
        let mut recipient = token_state(&bob_public_key, amount);
        recipient.insert(
            "extension_commitment".into(),
            extension_commitment.to_vec().into(),
        );
        let transfer = EntryCall::new("transfer").args_with(|tx, index| {
            let mut witness = vec![0x00];
            witness.extend(sign_input(tx, index, &alice));
            args!(vec![recipient.clone()], witness)
        });
        let sent = builder.build(
            &TxContext::new()
                .actor_input(
                    "KCC20",
                    minted_state,
                    transfer,
                    token.outpoint,
                    token.utxo,
                    0,
                )
                .actor_output(
                    "KCC20",
                    recipient.clone(),
                    CovenantBinding::new(0, token.covenant_id),
                    TOKEN_OUTPUT_SOMPI,
                ),
        )?;
        println!("transfer to Bob: {}", sent.id());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
