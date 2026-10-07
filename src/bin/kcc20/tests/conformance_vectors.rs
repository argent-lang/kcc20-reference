use super::*;
use argent::codec::{decode_hex, decode_runtime_state_script, encode_hex};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/kcc20/conformance.json"
    )))
    .unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    decode_hex(value.as_str().unwrap()).unwrap()
}

fn byte(value: &Value) -> u8 {
    let data = bytes(value);
    assert_eq!(data.len(), 1);
    data[0]
}

fn guard(value: &Value) -> [u8; 32] {
    bytes(value).try_into().unwrap()
}

fn state_from_json(value: &Value) -> TokenState {
    state! {
        amount: value["amount"].as_i64().unwrap(),
        owner: bytes(&value["owner_hex"]),
        owner_scheme: byte(&value["owner_scheme_hex"]),
        borrow_scheme: byte(&value["borrow_scheme_hex"]),
        borrow_guard: bytes(&value["borrow_guard_hex"]),
        extension_commitment: bytes(&value["extension_commitment_hex"]),
    }
}

fn dispatch_name(ty: &Value) -> String {
    match ty["kind"].as_str().unwrap() {
        "int" => "int".into(),
        "byte" => "byte".into(),
        "bytes" => "byte[]".into(),
        "fixed_bytes" => format!("byte[{}]", ty["len"].as_u64().unwrap()),
        "dynamic_array" => format!("{}[]", dispatch_name(&ty["item"])),
        "struct" => {
            let record = &artifact().sil_abi.structs[ty["name"].as_str().unwrap()];
            let fields: Vec<_> = record
                .fields
                .iter()
                .map(|field| dispatch_name(&serde_json::to_value(&field.ty).unwrap()))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        kind => panic!("unexpected dispatch type {kind}"),
    }
}

fn redeem_script(state: &TokenState) -> Vec<u8> {
    let abi = &artifact().sil_abi;
    let contract = &abi.contracts["KCC20"];
    let (prefix, _, suffix) = contract
        .compiled
        .script_parts(&contract.compiled.bytecode)
        .unwrap();
    let mut runtime_state = state.clone();
    runtime_state.insert(
        "gen__kcc20_template".into(),
        contract.compiled.template_hash.to_vec().into(),
    );
    let encoded =
        encode_runtime_state_script(abi, &contract.runtime_state, &runtime_state).unwrap();
    [prefix, encoded.as_slice(), suffix].concat()
}

// Re-sign after setting the vector's input KAS value, which the normal test helper fixes at 1000.
fn run_vm(transfer: &Transfer, leader_kas: u64) -> BuilderResult<Transaction> {
    let (transaction, mut entries) = transfer.signed_case()?;
    entries[0].amount = leader_kas;
    let mut tx = MutableTransaction::with_entries(transaction, entries.clone());
    for (index, input) in transfer.inputs.iter().enumerate() {
        let entry = if index == 0 {
            "transfer"
        } else {
            "transfer_delegator"
        };
        let witness = input.authorization.witness(&tx, index, index == 0);
        let args = if index == 0 {
            vec![
                transfer.outputs.as_slice().into_artifact_value(),
                witness.into(),
            ]
        } else {
            vec![witness.into()]
        };
        let encoded = encode_contract_entry_sig_script(&artifact().sil_abi, "KCC20", entry, &args)?;
        tx.tx.inputs[index].signature_script = pay_to_script_hash_signature_script_with_flags(
            redeem_script(&input.state),
            encoded,
            covenant_engine_flags(),
        )?;
    }
    execute_transaction_with_covenants(&mut tx.tx, entries)?;
    Ok(tx.tx)
}

fn assert_vm_outcome(case: &Value, transfer: &Transfer, leader_kas: u64) {
    let id = case["id"].as_str().unwrap();
    let result = run_vm(transfer, leader_kas);
    match case["result"].as_str().unwrap() {
        "accept" => {
            result.unwrap_or_else(|error| panic!("{id}: {error}"));
        }
        "reject" => {
            let error = result.expect_err(id);
            assert!(
                matches!(error, BuilderError::InputScript { input_index: 0, .. }),
                "{id}: expected input-0 script rejection, got {error}"
            );
        }
        result => panic!("unsupported outcome {result}"),
    }
    println!("VM {}: {}", id, case["result"].as_str().unwrap());
}

#[test]
fn conformance_dispatch_and_state_record() {
    let vectors = vectors();
    let abi = &artifact().sil_abi;
    let contract = &abi.contracts["KCC20"];
    let record = &abi.structs[vectors["state_record"]["name"].as_str().unwrap()];
    let types: Vec<_> = record
        .fields
        .iter()
        .map(|field| dispatch_name(&serde_json::to_value(&field.ty).unwrap()))
        .collect();
    assert_eq!(
        serde_json::to_value(&types).unwrap(),
        vectors["state_record"]["field_types"]
    );
    assert_eq!(
        format!("{{{}}}", types.join(",")),
        vectors["state_record"]["dispatch_type_name"]
    );
    for vector in vectors["dispatch"].as_array().unwrap() {
        let name = vector["entrypoint"].as_str().unwrap();
        let entry = &contract.entries[name];
        let params: Vec<_> = entry
            .params
            .iter()
            .map(|param| dispatch_name(&serde_json::to_value(&param.ty).unwrap()))
            .collect();
        let signature = format!("{name}({})", params.join(","));
        assert_eq!(signature, vector["function_signature"]);
        let digest = blake3::hash(signature.as_bytes());
        assert_eq!(
            encode_hex(&digest.as_bytes()[..4]),
            vector["dispatch_tag_hex"]
        );
        assert_eq!(entry.dispatch_tag.to_hex(), vector["dispatch_tag_hex"]);
        println!("dispatch {name}: {}", entry.dispatch_tag.to_hex());
    }
}

#[test]
fn conformance_state_and_transfer_argument_encoding() {
    let vectors = vectors();
    let abi = &artifact().sil_abi;
    let mut layout = abi.contracts["KCC20"].runtime_state.clone();
    layout
        .fields
        .retain(|field| field.name != "gen__kcc20_template");
    let state = state_from_json(&vectors["state_encoding"]["state"]);
    let encoded = encode_runtime_state_script(abi, &layout, &state).unwrap();
    assert_eq!(
        encoded.len() as u64,
        vectors["state_record"]["encoded_state_length"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(encoded, bytes(&vectors["state_encoding"]["encoded_hex"]));
    assert_eq!(
        decode_runtime_state_script(abi, &layout, &encoded).unwrap(),
        state
    );
    for (field, expected) in layout.fields.iter().zip(
        vectors["state_encoding"]["encoded_fields_hex"]
            .as_array()
            .unwrap(),
    ) {
        let mut single_field = layout.clone();
        single_field.fields = vec![field.clone()];
        let values = BTreeMap::from([(field.name.clone(), state[&field.name].clone())]);
        assert_eq!(
            encode_runtime_state_script(abi, &single_field, &values).unwrap(),
            bytes(expected)
        );
    }
    let arguments = &vectors["transfer_arguments"];
    let states: Vec<_> = arguments["next_states"]
        .as_array()
        .unwrap()
        .iter()
        .map(state_from_json)
        .collect();
    let witness = bytes(&arguments["witness_hex"]);
    let encoded = encode_contract_entry_sig_script(
        abi,
        "KCC20",
        "transfer",
        &[
            states.as_slice().into_artifact_value(),
            witness.clone().into(),
        ],
    )
    .unwrap();
    let mut expected = Vec::new();
    for push in arguments["grouped_field_pushes_hex"].as_array().unwrap() {
        expected.extend(bytes(push));
    }
    expected.extend(bytes(&arguments["witness_push_hex"]));
    expected.extend(bytes(&arguments["dispatch_tag_push_hex"]));
    assert_eq!(encoded, expected);
    assert_eq!(
        ScriptBuilder::new().add_data(&witness).unwrap().drain(),
        bytes(&arguments["witness_push_hex"])
    );
    println!("state encoding: all six field pushes, complete 112-byte state, and decoding match");
    println!("transfer arguments: all grouped field pushes, witness push, and tag push match");
}

fn normal_baseline(vectors: &Value) -> Transfer {
    let common = &vectors["standard_transfer"]["common"];
    let mut transfer = Transfer::normal();
    let mut leader = state_from_json(&common["leader_state"]);
    // Placeholder owners cannot be signed for; use a real key without changing authorization rules.
    leader.insert("owner".into(), demo_keys(0xaa).1.to_vec().into());
    transfer.inputs[0].state = leader;
    transfer.outputs = vectors["transfer_arguments"]["next_states"]
        .as_array()
        .unwrap()
        .iter()
        .map(state_from_json)
        .collect();
    transfer.output_values = vec![TOKEN_OUTPUT_SOMPI; transfer.outputs.len()];
    transfer
}

#[test]
fn conformance_standard_transfer_vm() {
    let vectors = vectors();
    run_vm(&normal_baseline(&vectors), TOKEN_OUTPUT_SOMPI)
        .expect("unmodified common transfer is valid with a real signature");
    for case in vectors["standard_transfer"]["cases"].as_array().unwrap() {
        let mut transfer = normal_baseline(&vectors);
        if let Some(amounts) = case["delegate_amounts"].as_array() {
            for amount in amounts {
                let (key, pubkey) = demo_keys(0xbb);
                transfer.inputs.push(Input {
                    state: token_state(&pubkey, amount.as_i64().unwrap()),
                    authorization: Authorization::Owner(key),
                });
            }
        }
        for (override_name, field_name) in [
            ("next_state_amounts", "amount"),
            ("next_state_owner_schemes_hex", "owner_scheme"),
            (
                "next_state_extension_commitments_hex",
                "extension_commitment",
            ),
        ] {
            if let Some(values) = case[override_name].as_array() {
                assert_eq!(values.len(), transfer.outputs.len());
                for (state, value) in transfer.outputs.iter_mut().zip(values) {
                    let value: ArtifactValue = match field_name {
                        "amount" => value.as_i64().unwrap().into(),
                        "owner_scheme" => byte(value).into(),
                        _ => bytes(value).into(),
                    };
                    state.insert(field_name.into(), value);
                }
            }
        }
        if !case["witness_hex"].is_null() {
            transfer.inputs[0].authorization = Authorization::Raw(bytes(&case["witness_hex"]));
        }
        assert_vm_outcome(case, &transfer, TOKEN_OUTPUT_SOMPI);
    }
}

#[test]
fn conformance_borrowed_receive_vm() {
    let vectors = vectors();
    let common = &vectors["borrowed_receive"]["common"];
    for case in vectors["borrowed_receive"]["cases"].as_array().unwrap() {
        let mut transfer = Transfer::borrowed(1);
        let leader_amount = common["leader_amount"].as_i64().unwrap();
        let successor_amount = case["successor_amount"].as_i64().unwrap();
        transfer.inputs[0]
            .state
            .insert("amount".into(), leader_amount.into());
        transfer.inputs[0]
            .state
            .insert("owner".into(), bytes(&common["owner_hex"]).into());
        transfer.inputs[0].state.insert(
            "owner_scheme".into(),
            byte(&common["owner_scheme_hex"]).into(),
        );
        transfer.inputs[0].state.insert(
            "extension_commitment".into(),
            bytes(&common["extension_commitment_hex"]).into(),
        );
        let scheme = byte(&case["borrow_scheme_hex"]);
        transfer.borrow_policy(scheme, guard(&case["leader_borrow_guard_hex"]));
        transfer.outputs[0] = transfer.inputs[0].state.clone();
        transfer.outputs[0].insert("amount".into(), successor_amount.into());
        transfer.outputs[0].insert(
            "borrow_guard".into(),
            bytes(&case["successor_borrow_guard_hex"]).into(),
        );
        if !case["successor_owner_hex"].is_null() {
            transfer.outputs[0].insert("owner".into(), bytes(&case["successor_owner_hex"]).into());
        }
        // Supply enough tokens to preserve totals even for the 501-token threshold vector.
        transfer.inputs[1]
            .state
            .insert("amount".into(), 2000i64.into());
        transfer.outputs[1].insert(
            "amount".into(),
            (leader_amount + 2000 - successor_amount).into(),
        );
        let leader_kas = case["leader_kas_value_sompi"]
            .as_u64()
            .unwrap_or(TOKEN_OUTPUT_SOMPI);
        transfer.output_values[0] = case["successor_kas_value_sompi"]
            .as_u64()
            .unwrap_or(leader_kas);
        if scheme == BORROW_HASH_CHAIN {
            let witness = bytes(&case["witness_hex"]);
            assert_eq!(witness.len(), 130);
            let next_guard = witness[1..33].try_into().unwrap();
            let intended_preimage = guard(&vectors["hash_chain"]["links"][1]["x_hex"]);
            let (key, _) = demo_keys(0xdd);
            let committed_guard = chain_guard(&intended_preimage, &key);
            // Substitute the one-time signing key and recompute its commitment;
            // preserve the vector's revealed link and deliberate successor mutations.
            transfer.inputs[0]
                .state
                .insert("borrow_guard".into(), committed_guard.to_vec().into());
            if case["successor_borrow_guard_hex"] == case["leader_borrow_guard_hex"] {
                transfer.outputs[0].insert("borrow_guard".into(), committed_guard.to_vec().into());
            }
            transfer.inputs[0].authorization = Authorization::HashChain { next_guard, key };
        } else {
            transfer.inputs[0].authorization = Authorization::Raw(bytes(&case["witness_hex"]));
        }
        assert_vm_outcome(case, &transfer, leader_kas);
    }
}

#[test]
fn conformance_owner_witnesses_and_p2pkh_hashes() {
    let vectors = vectors();
    for vector in vectors["owner_witness"].as_array().unwrap() {
        let raw = bytes(&vector["witness_hex"]);
        assert_eq!(raw.len() as u64, vector["length"].as_u64().unwrap());
        assert_eq!(raw[0], PATH_NORMAL);
        let scheme = byte(&vector["owner_scheme_hex"]);
        let mut transfer = Transfer::normal();
        if scheme == OWNER_P2SH {
            let (key, pubkey) = demo_keys(0xbb);
            transfer.inputs.push(Input {
                state: token_state(&pubkey, 100),
                authorization: Authorization::Owner(key),
            });
            transfer.outputs[0].insert("amount".into(), 200i64.into());
        }
        transfer.owner_scheme(0, scheme);
        let (transaction, entries) = transfer.signed_case().unwrap();
        let signed = MutableTransaction::with_entries(transaction, entries);
        let witness = transfer.inputs[0].authorization.witness(&signed, 0, true);
        assert_eq!(witness.len(), raw.len());
        if scheme == OWNER_P2SH || scheme == OWNER_COVENANT_ID {
            assert_eq!(witness, raw);
        }
        if !vector["p2pkh_hash_hex"].is_null() {
            let public_key_len = if scheme == OWNER_P2PKH_ECDSA { 33 } else { 32 };
            assert_eq!(
                encode_hex(blake3::hash(&raw[1..1 + public_key_len]).as_bytes()),
                vector["p2pkh_hash_hex"]
            );
        }
        run_vm(&transfer, TOKEN_OUTPUT_SOMPI).unwrap();
        println!(
            "owner witness {}: format, hash (where given), and VM authorization pass",
            vector["scheme"].as_str().unwrap()
        );
    }
}

#[test]
fn conformance_borrow_witnesses_and_hash_chain() {
    let vectors = vectors();
    let chain = &vectors["hash_chain"];
    let mut previous = bytes(&chain["x_0_hex"]);
    for (index, link) in chain["links"].as_array().unwrap().iter().enumerate() {
        assert_eq!(link["i"].as_u64().unwrap(), index as u64 + 1);
        let key = bytes(&link["pubkey_hex"]);
        let digest = blake3::hash(&[previous.as_slice(), key.as_slice()].concat());
        assert_eq!(encode_hex(digest.as_bytes()), link["x_hex"]);
        previous = digest.as_bytes().to_vec();
    }
    assert_eq!(previous, bytes(&chain["initial_borrow_guard_hex"]));
    for case in vectors["borrowed_receive"]["cases"].as_array().unwrap() {
        if !case["revealed_link_hash_hex"].is_null() {
            let witness = bytes(&case["witness_hex"]);
            assert_eq!(
                encode_hex(blake3::hash(&witness[1..65]).as_bytes()),
                case["revealed_link_hash_hex"]
            );
        }
    }
    for vector in vectors["borrow_witness"].as_array().unwrap() {
        let raw = bytes(&vector["witness_hex"]);
        assert_eq!(raw.len() as u64, vector["length"].as_u64().unwrap());
        assert_eq!(raw[0], PATH_BORROW);
        let scheme = byte(&vector["borrow_scheme_hex"]);
        let mut transfer = Transfer::borrowed(1);
        let (key, public_key) = demo_keys(0xdd);
        match scheme {
            BORROW_AMOUNT_THRESHOLD => {
                transfer.borrow_policy(scheme, [0; 32]);
                transfer.inputs[0].authorization = Authorization::Raw(raw.clone());
            }
            BORROW_SCHNORR_SIGNATURE => {
                transfer.borrow_policy(scheme, public_key);
                transfer.inputs[0].authorization = Authorization::BorrowSignature(key);
            }
            BORROW_HASH_CHAIN => {
                let next_guard = raw[1..33].try_into().unwrap();
                assert_eq!(&raw[1..33], bytes(&chain["links"][1]["x_hex"]));
                assert_eq!(&raw[33..65], bytes(&chain["links"][2]["pubkey_hex"]));
                transfer.borrow_policy(scheme, chain_guard(&next_guard, &key));
                transfer.outputs[0].insert("borrow_guard".into(), next_guard.to_vec().into());
                transfer.inputs[0].authorization = Authorization::HashChain { next_guard, key };
            }
            _ => panic!("unexpected borrow witness scheme"),
        }
        let (transaction, entries) = transfer.signed_case().unwrap();
        let signed = MutableTransaction::with_entries(transaction, entries);
        let witness = transfer.inputs[0].authorization.witness(&signed, 0, true);
        assert_eq!(witness.len(), raw.len());
        run_vm(&transfer, TOKEN_OUTPUT_SOMPI).unwrap();
        println!(
            "borrow witness {}: format and VM authorization pass",
            vector["scheme"].as_str().unwrap()
        );
    }
    println!("hash chain: all three links, initial commitment, and mismatch hash match");
}
