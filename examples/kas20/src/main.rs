use argent::genesis::{ArgentCovenantBootstrap, ArgentGenesisPackage, GenesisProofPackage};
use argent_runtime::{CovenantOutput, EntryCall, TxBuilder, TxContext, args};
use kas20::{
    GENESIS_GROUP, MINTER_VALUE, Result, SOMPI_PER_KAS, backed_value, compile, minter_state,
    token_state,
};
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, UtxoEntry};
use kcc20_reference::demo_support::{demo_keys, demo_outpoint, sign_input};
use std::{fs, path::PathBuf};

fn ordinary(value: u64) -> UtxoEntry {
    UtxoEntry::new(
        value,
        ScriptPublicKey::from_vec(0, vec![0x51]),
        1,
        false,
        None,
    )
}
fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some(command @ ("build" | "fixtures")) if args.next().is_none() => {
            let output = root.join(if command == "fixtures" {
                "fixtures"
            } else {
                "build/kas20"
            });
            compile(&output)?;
            println!("compiled KAS20 contracts into {}", output.display());
        }
        Some("demo") if args.next().is_none() => demo()?,
        _ => {
            return Err("usage: kas20 build | fixtures | demo".into());
        }
    }
    Ok(())
}

fn demo() -> Result<()> {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("build/kas20-demo");
    fs::create_dir_all(&output)?;
    let compiled = compile(output.join("contracts"))?;
    let bundle = compiled.runtime_bundle()?;
    let builder = TxBuilder::from_bundle(&bundle)?;
    let (alice, owner) = demo_keys(0xaa);
    let (bob_key, bob) = demo_keys(0xbb);
    let script = ScriptPublicKey::from_vec(0, vec![0x51]);
    let context = TxContext::new()
        .input(
            demo_outpoint(1, 0),
            ordinary(4 * MINTER_VALUE),
            Vec::new(),
            0,
        )
        .actor_genesis_output(
            0,
            GENESIS_GROUP,
            "PublicMint",
            minter_state(&owner),
            MINTER_VALUE,
        )
        .output(script.clone(), None, 3 * MINTER_VALUE - MINTER_VALUE / 10);
    let bootstrap = ArgentCovenantBootstrap::from_context(&bundle, &context, 0, GENESIS_GROUP)?;
    let genesis = builder.build(&context)?;
    let minter = CovenantOutput::from_tx(&genesis, 0)?;
    let id = minter.covenant_id;
    let argent = GenesisProofPackage::new(ArgentGenesisPackage::new(
        &bundle,
        bootstrap.clone().compose(&bundle)?,
    ));
    argent.verify_argent(id)?;
    fs::write(
        output.join("genesis.json"),
        serde_json::to_vec_pretty(&genesis)?,
    )?;
    fs::write(
        output.join("bootstrap.json"),
        serde_json::to_vec_pretty(&bootstrap)?,
    )?;
    fs::write(output.join("argent-genesis.json"), argent.to_json()?)?;
    let binding = CovenantBinding::new(0, id);
    let amount = SOMPI_PER_KAS;
    let mut receiving_state = token_state(&bob, amount);
    receiving_state.insert("borrow_scheme".into(), 1u8.into());
    let mint_receiver = builder.build(
        &TxContext::new()
            .actor_input(
                "PublicMint",
                minter_state(&owner),
                EntryCall::new("mint").args(args!(receiving_state.clone())),
                minter.outpoint,
                minter.utxo,
                0,
            )
            .input(
                demo_outpoint(2, 0),
                ordinary(backed_value(amount)?),
                Vec::new(),
                0,
            )
            .actor_output("PublicMint", minter_state(&owner), binding, MINTER_VALUE)
            .actor_output(
                "KAS20",
                receiving_state.clone(),
                binding,
                backed_value(amount)?,
            ),
    )?;
    let minter = CovenantOutput::from_tx(&mint_receiver, 0)?;
    let receiver = CovenantOutput::from_tx(&mint_receiver, 1)?;
    // Anyone can split a minter into two independently spendable minters.
    let split = builder.build(
        &TxContext::new()
            .actor_input(
                "PublicMint",
                minter_state(&owner),
                EntryCall::new("split").args(args!(bob.to_vec())),
                minter.outpoint,
                minter.utxo,
                0,
            )
            .input(demo_outpoint(3, 0), ordinary(MINTER_VALUE), Vec::new(), 0)
            .actor_output("PublicMint", minter_state(&owner), binding, MINTER_VALUE)
            .actor_output("PublicMint", minter_state(&bob), binding, MINTER_VALUE),
    )?;
    let minter = CovenantOutput::from_tx(&split, 1)?;
    let minter_value = MINTER_VALUE / 2;
    let rebalanced = builder.build(
        &TxContext::new()
            .actor_input(
                "PublicMint",
                minter_state(&bob),
                EntryCall::new("rebalance_value")
                    .args_with(move |tx, index| args!(sign_input(tx, index, &bob_key))),
                minter.outpoint,
                minter.utxo,
                0,
            )
            .actor_output("PublicMint", minter_state(&bob), binding, minter_value)
            .output(script.clone(), None, MINTER_VALUE - minter_value),
    )?;
    let minter = CovenantOutput::from_tx(&rebalanced, 0)?;
    let minted_state = token_state(&owner, amount);
    let mint = builder.build(
        &TxContext::new()
            .actor_input(
                "PublicMint",
                minter_state(&bob),
                EntryCall::new("mint").args(args!(minted_state.clone())),
                minter.outpoint,
                minter.utxo,
                0,
            )
            .input(
                demo_outpoint(4, 0),
                ordinary(backed_value(amount)?),
                Vec::new(),
                0,
            )
            .actor_output("PublicMint", minter_state(&bob), binding, minter_value)
            .actor_output(
                "KAS20",
                minted_state.clone(),
                binding,
                backed_value(amount)?,
            ),
    )?;
    let token = CovenantOutput::from_tx(&mint, 1)?;
    let mut sent_state = receiving_state.clone();
    let received_amount = 2 * amount;
    sent_state.insert("amount".into(), received_amount.into());
    let transfer = builder.build(
        &TxContext::new()
            .actor_input(
                "KAS20",
                receiving_state,
                EntryCall::new("transfer").args(args!(vec![sent_state.clone()], vec![1u8])),
                receiver.outpoint,
                receiver.utxo,
                0,
            )
            .actor_input(
                "KAS20",
                minted_state,
                EntryCall::new("transfer_delegator")
                    .args_with(move |tx, index| args!(sign_input(tx, index, &alice))),
                token.outpoint,
                token.utxo,
                0,
            )
            .actor_output(
                "KAS20",
                sent_state.clone(),
                binding,
                backed_value(received_amount)?,
            ),
    )?;
    let token = CovenantOutput::from_tx(&transfer, 0)?;
    let burned = builder.build(
        &TxContext::new()
            .actor_input(
                "KAS20",
                sent_state,
                EntryCall::new("burn")
                    .args_with(move |tx, index| args!(sign_input(tx, index, &bob_key))),
                token.outpoint,
                token.utxo,
                0,
            )
            .output(script, None, backed_value(received_amount)?),
    )?;
    for (name, tx) in [
        ("mint_receiver", mint_receiver),
        ("split", split),
        ("rebalance_value", rebalanced),
        ("mint", mint),
        ("transfer", transfer),
        ("burn", burned),
    ] {
        fs::write(
            output.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&tx)?,
        )?;
    }
    println!("KAS20 (symbol KAS), 8 decimals; synthetic offline demo completed");
    println!("covenant ID: {id}");
    println!(
        "minted 1 KAS20 to Bob, split and rebalanced minter, minted and transferred 1 KAS20 from Alice, burned 2 KAS20 for 2 KAS"
    );
    println!(
        "genesis proof: {}",
        output.join("argent-genesis.json").display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_demo() -> Result<()> {
        demo()?;
        let output = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("build/kas20-demo");
        for name in [
            "genesis",
            "mint_receiver",
            "split",
            "rebalance_value",
            "mint",
            "transfer",
            "burn",
        ] {
            let tx: kaspa_consensus_core::tx::Transaction =
                serde_json::from_slice(&fs::read(output.join(format!("{name}.json")))?)?;
            for (index, recipient) in tx.outputs.iter().enumerate() {
                assert!(recipient.value > 0, "{name} output {index} has zero value");
            }
        }
        Ok(())
    }
}
