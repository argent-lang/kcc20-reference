use std::sync::OnceLock;

use argent::{
    artifact::Artifact,
    codec::{encode_contract_entry_sig_script, encode_runtime_state_script},
};
use argent_runtime::{
    BuilderError, BuilderResult, IntoArtifactValue, covenant_engine_flags,
    execute_input_with_covenants, execute_transaction_with_covenants,
};
use kaspa_consensus_core::{
    hashing::{
        sighash::{
            SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash,
        },
        sighash_type::{SIG_HASH_ALL, SigHashType},
    },
    tx::{MutableTransaction, ScriptPublicKey, Transaction, TransactionOutput, UtxoEntry},
};
use kaspa_txscript::{
    pay_to_script_hash_script, pay_to_script_hash_signature_script_with_flags,
    script_builder::ScriptBuilder, serialize_i64,
};
use secp256k1::{Keypair, Message, Secp256k1};

use super::*;

mod conformance_vectors;

const PATH_NORMAL: u8 = 0x00;
const OWNER_P2PKH_SCHNORR: u8 = 0x01;
const OWNER_P2PKH_ECDSA: u8 = 0x02;
const OWNER_P2SH: u8 = 0x03;
const OWNER_COVENANT_ID: u8 = 0x04;
const BORROW_SCHNORR_SIGNATURE: u8 = 0x02;
const BORROW_HASH_CHAIN: u8 = 0x03;

pub(super) fn artifact() -> &'static Artifact {
    static ARTIFACT: OnceLock<Artifact> = OnceLock::new();
    ARTIFACT.get_or_init(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        build_file(
            root.join("contracts/public_mint.ag"),
            root.join("build/test-reference"),
        )
        .expect("public-mint app compiles")
    })
}

fn covenant_id() -> Hash {
    Hash::from_bytes([0x11; 32])
}

fn public_key_hash(public_key: &[u8]) -> [u8; 32] {
    *blake3::hash(public_key).as_bytes()
}

fn chain_guard(next_guard: &[u8; 32], key: &Keypair) -> [u8; 32] {
    let mut preimage = next_guard.to_vec();
    preimage.extend(key.x_only_public_key().0.serialize());
    *blake3::hash(&preimage).as_bytes()
}

fn threshold_guard(threshold: i64) -> [u8; 32] {
    let mut guard = [0x42; 32];
    guard[..8].copy_from_slice(&serialize_i64(threshold, Some(8)).unwrap());
    guard
}

fn schnorr_signature(
    tx: &MutableTransaction<Transaction>,
    index: usize,
    key: &Keypair,
    hash_type: SigHashType,
) -> Vec<u8> {
    if hash_type.to_u8() == SIG_HASH_ALL.to_u8() {
        return sign_input(tx, index, key);
    }
    let digest = calc_schnorr_signature_hash(
        &tx.as_verifiable(),
        index,
        hash_type,
        &SigHashReusedValuesUnsync::new(),
    );
    let mut signature = key
        .sign_schnorr(Message::from_digest(digest.as_bytes()))
        .as_ref()
        .to_vec();
    signature.push(hash_type.to_u8());
    signature
}

enum Authorization {
    Owner(Keypair),
    P2pkhSchnorr(Keypair),
    P2pkhEcdsa(Keypair),
    BorrowSignature(Keypair),
    HashChain { next_guard: [u8; 32], key: Keypair },
    Raw(Vec<u8>),
}

impl Authorization {
    fn witness(&self, tx: &MutableTransaction<Transaction>, index: usize, leader: bool) -> Vec<u8> {
        self.witness_with_hash_type(tx, index, leader, SIG_HASH_ALL)
    }

    fn witness_with_hash_type(
        &self,
        tx: &MutableTransaction<Transaction>,
        index: usize,
        leader: bool,
        hash_type: SigHashType,
    ) -> Vec<u8> {
        let mut witness = match self {
            Self::Raw(bytes) => return bytes.clone(),
            Self::BorrowSignature(_) | Self::HashChain { .. } => vec![PATH_BORROW],
            _ if leader => vec![PATH_NORMAL],
            _ => Vec::new(),
        };
        match self {
            Self::Owner(key) | Self::BorrowSignature(key) => {
                witness.extend(schnorr_signature(tx, index, key, hash_type));
            }
            Self::P2pkhSchnorr(key) => {
                witness.extend(key.x_only_public_key().0.serialize());
                witness.extend(schnorr_signature(tx, index, key, hash_type));
            }
            Self::P2pkhEcdsa(key) => {
                witness.extend(key.public_key().serialize());
                let digest = calc_ecdsa_signature_hash(
                    &tx.as_verifiable(),
                    index,
                    hash_type,
                    &SigHashReusedValuesUnsync::new(),
                );
                let signature = Secp256k1::new()
                    .sign_ecdsa(&Message::from_digest(digest.as_bytes()), &key.secret_key());
                witness.extend(signature.serialize_compact());
                witness.push(hash_type.to_u8());
            }
            Self::HashChain { next_guard, key } => {
                witness.extend(next_guard);
                witness.extend(key.x_only_public_key().0.serialize());
                witness.extend(schnorr_signature(tx, index, key, hash_type));
            }
            Self::Raw(_) => unreachable!(),
        }
        witness
    }
}

struct Input {
    state: TokenState,
    authorization: Authorization,
}

struct Transfer {
    inputs: Vec<Input>,
    outputs: Vec<TokenState>,
    output_values: Vec<u64>,
    declared_states: Option<Vec<TokenState>>,
    authority: Option<(UtxoEntry, Vec<u8>)>,
    entries: Option<Vec<&'static str>>,
    output_bindings: Option<Vec<CovenantBinding>>,
    ordinary_prefix: bool,
    signature_hash_type: SigHashType,
}

impl Transfer {
    fn normal() -> Self {
        let (alice, public_key) = demo_keys(0xaa);
        let state = token_state(&public_key, 100);
        Self {
            inputs: vec![Input {
                state: state.clone(),
                authorization: Authorization::Owner(alice),
            }],
            outputs: vec![state],
            output_values: vec![TOKEN_OUTPUT_SOMPI],
            declared_states: None,
            authority: None,
            entries: None,
            output_bindings: None,
            ordinary_prefix: false,
            signature_hash_type: SIG_HASH_ALL,
        }
    }

    fn borrowed(increase: i64) -> Self {
        let (alice, alice_public_key) = demo_keys(0xaa);
        let (_, bob_public_key) = demo_keys(0xbb);
        Self {
            inputs: vec![
                Input {
                    state: threshold_token_state(&bob_public_key, 200, 10),
                    authorization: Authorization::Raw(vec![PATH_BORROW]),
                },
                Input {
                    state: token_state(&alice_public_key, 100),
                    authorization: Authorization::Owner(alice),
                },
            ],
            outputs: vec![
                threshold_token_state(&bob_public_key, 200 + increase, 10),
                token_state(&alice_public_key, 100 - increase),
            ],
            output_values: vec![TOKEN_OUTPUT_SOMPI; 2],
            declared_states: None,
            authority: None,
            entries: None,
            output_bindings: None,
            ordinary_prefix: false,
            signature_hash_type: SIG_HASH_ALL,
        }
    }

    fn borrow_policy(&mut self, scheme: u8, guard: [u8; 32]) {
        for state in [&mut self.inputs[0].state, &mut self.outputs[0]] {
            state.insert("borrow_scheme".into(), scheme.into());
            state.insert("borrow_guard".into(), guard.to_vec().into());
        }
    }

    fn owner_scheme(&mut self, index: usize, scheme: u8) {
        let (key, public_key) = demo_keys(0xaa);
        let (owner, authorization) = match scheme {
            OWNER_P2PK_SCHNORR => (public_key, Authorization::Owner(key)),
            OWNER_P2PKH_SCHNORR => (
                public_key_hash(&public_key),
                Authorization::P2pkhSchnorr(key),
            ),
            OWNER_P2PKH_ECDSA => (
                public_key_hash(&key.public_key().serialize()),
                Authorization::P2pkhEcdsa(key),
            ),
            OWNER_P2SH => {
                // OP_TRUE illustrates the minimum P2SH participation rule.
                let redeem_script = vec![0x51];
                let script = pay_to_script_hash_script(&redeem_script);
                // The standard envelope is OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL.
                let owner = script.script()[2..34].try_into().unwrap();
                let mut witness = if index == 0 {
                    vec![PATH_NORMAL]
                } else {
                    Vec::new()
                };
                let authority_index = self.inputs.len() + usize::from(self.ordinary_prefix);
                witness.push(u8::try_from(authority_index).unwrap());
                let signature_script = ScriptBuilder::new()
                    .add_data(&redeem_script)
                    .unwrap()
                    .drain();
                self.authority = Some((
                    UtxoEntry::new(1_000, script, 1, false, None),
                    signature_script,
                ));
                (owner, Authorization::Raw(witness))
            }
            OWNER_COVENANT_ID => (
                covenant_id().as_bytes(),
                Authorization::Raw(if index == 0 {
                    vec![PATH_NORMAL]
                } else {
                    Vec::new()
                }),
            ),
            _ => panic!("unsupported test owner scheme"),
        };
        self.inputs[index]
            .state
            .insert("owner_scheme".into(), scheme.into());
        self.inputs[index]
            .state
            .insert("owner".into(), owner.to_vec().into());
        self.inputs[index].authorization = authorization;
    }

    // Encode witnesses directly so malformed cases reach the VM, not builder checks.
    fn signed_case(&self) -> BuilderResult<(Transaction, Vec<UtxoEntry>)> {
        assert_eq!(self.outputs.len(), self.output_values.len());
        if let Some(bindings) = &self.output_bindings {
            assert_eq!(bindings.len(), self.outputs.len());
        }
        if let Some(entries) = &self.entries {
            assert_eq!(entries.len(), self.inputs.len());
        }
        let abi = &artifact().sil_abi;
        let contract = &abi.contracts["KCC20"];
        let (prefix, _, suffix) = contract
            .compiled
            .script_parts(&contract.compiled.bytecode)
            .expect("compiled contract has a state span");
        let redeem_script = |state: &TokenState| -> BuilderResult<Vec<u8>> {
            let mut runtime_state = state.clone();
            runtime_state.insert(
                "gen__kcc20_template".into(),
                contract.compiled.template_hash.to_vec().into(),
            );
            let state = encode_runtime_state_script(abi, &contract.runtime_state, &runtime_state)?;
            Ok([prefix, state.as_slice(), suffix].concat())
        };
        let mut inputs = Vec::new();
        let mut utxos = Vec::new();
        let mut outputs = Vec::new();
        let input_offset = usize::from(self.ordinary_prefix);
        if self.ordinary_prefix {
            let script = ScriptPublicKey::from_vec(0, vec![0x51]);
            inputs.push(TxBuilder::transaction_input(
                demo_outpoint(3, 0),
                Vec::new(),
            ));
            utxos.push(UtxoEntry::new(1_000, script.clone(), 1, false, None));
            outputs.push(TransactionOutput::new(1_000, script));
        }
        for (index, input) in self.inputs.iter().enumerate() {
            let script = pay_to_script_hash_script(&redeem_script(&input.state)?);
            inputs.push(TxBuilder::transaction_input(
                demo_outpoint(1, index as u32),
                Vec::new(),
            ));
            utxos.push(UtxoEntry::new(
                TOKEN_OUTPUT_SOMPI,
                script,
                1,
                false,
                Some(covenant_id()),
            ));
        }
        if let Some((utxo, witness)) = &self.authority {
            inputs.push(TxBuilder::transaction_input(
                demo_outpoint(2, 0),
                witness.clone(),
            ));
            utxos.push(utxo.clone());
        }
        for (index, (state, value)) in self.outputs.iter().zip(&self.output_values).enumerate() {
            let mut output =
                TransactionOutput::new(*value, pay_to_script_hash_script(&redeem_script(state)?));
            output.covenant = Some(self.output_bindings.as_ref().map_or(
                CovenantBinding::new(input_offset as u16, covenant_id()),
                |bindings| bindings[index],
            ));
            outputs.push(output);
        }
        let mut unsigned = MutableTransaction::with_entries(
            TxBuilder::transaction(inputs, outputs),
            utxos.clone(),
        );
        let declared = self.declared_states.as_ref().unwrap_or(&self.outputs);
        let next_states = declared.as_slice().into_artifact_value();
        for (index, input) in self.inputs.iter().enumerate() {
            let input_index = index + input_offset;
            let entry = self.entries.as_ref().map_or(
                if index == 0 {
                    "transfer"
                } else {
                    "transfer_delegator"
                },
                |entries| entries[index],
            );
            let witness = input.authorization.witness_with_hash_type(
                &unsigned,
                input_index,
                entry == "transfer",
                self.signature_hash_type,
            );
            let args = if entry == "transfer" {
                vec![next_states.clone(), witness.into()]
            } else {
                vec![witness.into()]
            };
            let args = encode_contract_entry_sig_script(abi, "KCC20", entry, &args)?;
            unsigned.tx.inputs[input_index].signature_script =
                pay_to_script_hash_signature_script_with_flags(
                    redeem_script(&input.state)?,
                    args,
                    covenant_engine_flags(),
                )?;
        }
        Ok((unsigned.tx, utxos))
    }

    fn build(&self) -> BuilderResult<Transaction> {
        let (mut transaction, utxos) = self.signed_case()?;
        execute_transaction_with_covenants(&mut transaction, utxos)?;
        Ok(transaction)
    }

    fn rejects_at(&self, expected_input: usize) {
        let error = self.build().expect_err("invalid transfer must fail");
        assert!(
            matches!(error, BuilderError::InputScript { input_index, .. } if input_index == expected_input),
            "expected script rejection at input {expected_input}, got {error}",
        );
    }
}

#[test]
fn leader_and_delegate_accept_each_owner_scheme() {
    for scheme in 0..=OWNER_COVENANT_ID {
        let mut transfer = Transfer::normal();
        transfer.owner_scheme(0, scheme);
        transfer
            .build()
            .unwrap_or_else(|error| panic!("leader scheme {scheme:#04x}: {error}"));

        let mut transfer = Transfer::borrowed(11);
        transfer.owner_scheme(1, scheme);
        transfer
            .build()
            .unwrap_or_else(|error| panic!("delegate scheme {scheme:#04x}: {error}"));
    }
}

#[test]
fn p2pkh_rejects_legacy_domain_hashes_for_both_roles() {
    let (key, schnorr_public_key) = demo_keys(0xaa);
    let mut legacy_domain = [0u8; 32];
    legacy_domain[..13].copy_from_slice(b"PublicKeyHash");
    for scheme in [OWNER_P2PKH_SCHNORR, OWNER_P2PKH_ECDSA] {
        let public_key = if scheme == OWNER_P2PKH_SCHNORR {
            schnorr_public_key.to_vec()
        } else {
            key.public_key().serialize().to_vec()
        };
        let legacy_owner = blake3::keyed_hash(&legacy_domain, &public_key);
        for index in [0, 1] {
            let mut transfer = if index == 0 {
                Transfer::normal()
            } else {
                Transfer::borrowed(11)
            };
            transfer.owner_scheme(index, scheme);
            transfer.inputs[index]
                .state
                .insert("owner".into(), legacy_owner.as_bytes().to_vec().into());
            transfer.rejects_at(index);
        }
    }
}

#[test]
fn owner_authorization_rejects_wrong_keys_and_missing_authorities() {
    let (wrong_key, _) = demo_keys(0xcc);
    let mut transfer = Transfer::normal();
    transfer.inputs[0].authorization = Authorization::Owner(wrong_key);
    transfer.rejects_at(0);
    for scheme in [OWNER_P2PKH_SCHNORR, OWNER_P2PKH_ECDSA] {
        let mut transfer = Transfer::normal();
        transfer.inputs[0]
            .state
            .insert("owner_scheme".into(), scheme.into());
        transfer.inputs[0].authorization = if scheme == OWNER_P2PKH_SCHNORR {
            Authorization::P2pkhSchnorr(wrong_key)
        } else {
            Authorization::P2pkhEcdsa(wrong_key)
        };
        transfer.rejects_at(0);
    }
    for (scheme, witness) in [
        (OWNER_P2SH, vec![PATH_NORMAL, 255]),
        (OWNER_COVENANT_ID, vec![PATH_NORMAL]),
    ] {
        let mut transfer = Transfer::normal();
        transfer.inputs[0]
            .state
            .insert("owner_scheme".into(), scheme.into());
        transfer.inputs[0].authorization = Authorization::Raw(witness);
        transfer.rejects_at(0);
    }
}

#[test]
fn transfer_rejects_amount_and_extension_mismatches() {
    for amount in [99i64, 101, -1] {
        let mut transfer = Transfer::normal();
        transfer.outputs[0].insert("amount".into(), amount.into());
        transfer.rejects_at(0);
    }
    let mut transfer = Transfer::borrowed(11);
    transfer.inputs[1]
        .state
        .insert("extension_commitment".into(), vec![0x42u8; 32].into());
    transfer.rejects_at(0);
    let mut transfer = Transfer::normal();
    transfer.outputs[0].insert("extension_commitment".into(), vec![0x42u8; 32].into());
    transfer.rejects_at(0);
}

#[test]
fn transfer_preserves_any_shared_extension_commitment() {
    let mut transfer = Transfer::borrowed(11);
    for input in &mut transfer.inputs {
        input
            .state
            .insert("extension_commitment".into(), vec![0x42u8; 32].into());
    }
    for output in &mut transfer.outputs {
        output.insert("extension_commitment".into(), vec![0x42u8; 32].into());
    }
    transfer.build().unwrap();
}

#[test]
fn transfer_validates_output_schemes_across_full_byte_domain() {
    for (field, minimum, maximum) in [
        ("owner_scheme", OWNER_P2PK_SCHNORR, OWNER_COVENANT_ID),
        ("borrow_scheme", BORROW_DISABLED, BORROW_HASH_CHAIN),
    ] {
        for scheme in u8::MIN..=u8::MAX {
            let mut transfer = Transfer::normal();
            transfer.outputs[0].insert(field.into(), scheme.into());
            let result = transfer.build();

            if (minimum..=maximum).contains(&scheme) {
                assert!(
                    result.is_ok(),
                    "valid {field} {scheme:#04x} was rejected: {result:?}",
                );
            } else {
                assert!(
                    matches!(
                        &result,
                        Err(BuilderError::InputScript { input_index: 0, .. })
                    ),
                    "invalid {field} {scheme:#04x} must fail in the VM at input 0: {result:?}",
                );
            }
        }
    }
}

#[test]
fn transfer_rejects_invalid_output_policies() {
    for field in ["owner_scheme", "borrow_scheme"] {
        let mut transfer = Transfer::normal();
        transfer.outputs[0].insert(field.into(), 0xffu8.into());
        transfer.rejects_at(0);
    }
}

#[test]
fn normal_transfers_accept_negative_threshold_guards() {
    for threshold in [-i64::MAX, -10, -1] {
        let mut transfer = Transfer::normal();
        transfer.outputs[0].insert("borrow_scheme".into(), BORROW_AMOUNT_THRESHOLD.into());
        transfer.outputs[0].insert(
            "borrow_guard".into(),
            threshold_guard(threshold).to_vec().into(),
        );
        transfer.build().unwrap();

        // The owner can also spend the state without invoking its borrow policy.
        transfer.inputs[0].state = transfer.outputs[0].clone();
        transfer.build().unwrap();
    }
}

#[test]
fn transfer_rejects_malformed_leader_witnesses() {
    for witness in [vec![], vec![0xff], vec![PATH_NORMAL], vec![PATH_NORMAL; 67]] {
        let mut transfer = Transfer::normal();
        transfer.inputs[0].authorization = Authorization::Raw(witness);
        transfer.rejects_at(0);
    }
}

#[test]
fn transfer_binds_declared_states_to_actual_outputs() {
    let mut transfer = Transfer::normal();
    transfer.declared_states = Some(transfer.outputs.clone());
    transfer.outputs[0].insert("owner".into(), vec![0x42u8; 32].into());
    transfer.rejects_at(0);
}

#[test]
fn threshold_borrow_requires_a_strict_increase() {
    Transfer::borrowed(11).build().unwrap();
    for increase in [0, 5, 10] {
        Transfer::borrowed(increase).rejects_at(0);
    }
    let mut transfer = Transfer::borrowed(1);
    transfer.borrow_policy(BORROW_AMOUNT_THRESHOLD, [0; 32]);
    transfer.build().unwrap();
}

#[test]
fn threshold_borrow_clamps_nonpositive_thresholds_to_zero() {
    for threshold in [-i64::MAX, -10, -1, 0] {
        let mut guard = threshold_guard(threshold);
        if threshold == 0 {
            guard[7] = 0x80; // Fixed-width signed-magnitude negative zero.
        }
        for increase in [-1, 0, 1] {
            let mut transfer = Transfer::borrowed(increase);
            transfer.borrow_policy(BORROW_AMOUNT_THRESHOLD, guard);
            if increase > 0 {
                transfer.build().unwrap();
            } else {
                transfer.rejects_at(0);
            }
        }
    }
}

#[test]
fn threshold_uses_only_the_first_eight_guard_bytes() {
    let mut transfer = Transfer::borrowed(11);
    let mut guard = [0x42; 32];
    guard[..8].copy_from_slice(&10i64.to_le_bytes());
    transfer.borrow_policy(BORROW_AMOUNT_THRESHOLD, guard);
    transfer.build().unwrap();
}

#[test]
fn borrowed_receive_preserves_owner_policy_and_sompi() {
    for (field, value) in [
        ("owner", vec![0x42u8; 32].into()),
        ("owner_scheme", OWNER_COVENANT_ID.into()),
        ("borrow_scheme", BORROW_DISABLED.into()),
        ("borrow_guard", vec![0u8; 32].into()),
    ] {
        let mut transfer = Transfer::borrowed(11);
        transfer.outputs[0].insert(field.into(), value);
        transfer.rejects_at(0);
    }
    let mut transfer = Transfer::borrowed(11);
    transfer.output_values[0] -= 1;
    transfer.output_values[1] += 1;
    transfer.rejects_at(0);
    let mut transfer = Transfer::borrowed(11);
    transfer.outputs.swap(0, 1);
    transfer.rejects_at(0);
}

#[test]
fn borrowed_receive_still_requires_delegate_authorization() {
    let mut transfer = Transfer::borrowed(11);
    transfer.inputs[1].authorization = Authorization::Owner(demo_keys(0xcc).0);
    transfer.rejects_at(1);
    transfer.inputs[1].authorization = Authorization::Raw(vec![PATH_BORROW]);
    transfer.rejects_at(1);
}

#[test]
fn disabled_borrow_and_unexpected_threshold_witness_are_rejected() {
    let mut transfer = Transfer::borrowed(11);
    transfer.borrow_policy(BORROW_DISABLED, [0; 32]);
    transfer.rejects_at(0);
    let mut transfer = Transfer::borrowed(11);
    transfer.inputs[0].authorization = Authorization::Raw(vec![PATH_BORROW, 0]);
    transfer.rejects_at(0);
}

#[test]
fn signature_borrow_requires_the_guard_key_and_positive_increase() {
    let (key, public_key) = demo_keys(0xcc);
    let mut transfer = Transfer::borrowed(1);
    transfer.borrow_policy(BORROW_SCHNORR_SIGNATURE, public_key);
    transfer.inputs[0].authorization = Authorization::BorrowSignature(key);
    transfer.build().unwrap();
    transfer.inputs[0].authorization = Authorization::BorrowSignature(demo_keys(0xdd).0);
    transfer.rejects_at(0);
    transfer.inputs[0].authorization = Authorization::Raw(vec![PATH_BORROW]);
    transfer.rejects_at(0);
    let mut transfer = Transfer::borrowed(0);
    transfer.borrow_policy(BORROW_SCHNORR_SIGNATURE, public_key);
    transfer.inputs[0].authorization = Authorization::BorrowSignature(key);
    transfer.rejects_at(0);
}

#[test]
fn hash_chain_borrow_advances_guard_and_rejects_reused_links() {
    let (key, _) = demo_keys(0xcc);
    let next_guard = [0x42; 32];
    let current_guard = chain_guard(&next_guard, &key);
    let mut transfer = Transfer::borrowed(1);
    transfer.borrow_policy(BORROW_HASH_CHAIN, current_guard);
    transfer.outputs[0].insert("borrow_guard".into(), next_guard.to_vec().into());
    transfer.inputs[0].authorization = Authorization::HashChain { next_guard, key };
    transfer.build().unwrap();

    transfer.outputs[0].insert("borrow_guard".into(), current_guard.to_vec().into());
    transfer.rejects_at(0);
    transfer.outputs[0].insert("borrow_guard".into(), next_guard.to_vec().into());
    transfer.inputs[0].authorization = Authorization::HashChain {
        next_guard: [0x43; 32],
        key,
    };
    transfer.rejects_at(0);
    transfer.inputs[0].authorization = Authorization::HashChain {
        next_guard,
        key: demo_keys(0xdd).0,
    };
    transfer.rejects_at(0);

    // Once the successor holds next_guard, the old link no longer matches it.
    transfer.inputs[0].state = transfer.outputs[0].clone();
    transfer.outputs[0].insert("amount".into(), 202i64.into());
    transfer.outputs[1].insert("amount".into(), 99i64.into());
    transfer.inputs[0].authorization = Authorization::HashChain { next_guard, key };
    transfer.rejects_at(0);
}

#[test]
fn transfer_rejects_overflowing_totals() {
    let mut transfer = Transfer::borrowed(11);
    transfer.inputs[0]
        .state
        .insert("amount".into(), i64::MAX.into());
    transfer.outputs[0].insert("amount".into(), i64::MAX.into());
    transfer.outputs[1].insert("amount".into(), 100i64.into());
    transfer.rejects_at(0);
}

#[test]
fn transfer_rejects_out_of_range_input_and_output_counts() {
    let mut transfer = Transfer::normal();
    for seed in [0xbb, 0xcc, 0xdd] {
        let (key, public_key) = demo_keys(seed);
        transfer.inputs.push(Input {
            state: token_state(&public_key, 100),
            authorization: Authorization::Owner(key),
        });
    }
    transfer.outputs[0].insert("amount".into(), 400i64.into());
    transfer.rejects_at(0);
    for output_count in [0, 4] {
        let mut transfer = Transfer::normal();
        let state = token_state(&demo_keys(0xaa).1, 25);
        transfer.outputs = vec![state; output_count];
        transfer.output_values = vec![250; output_count];
        transfer.rejects_at(0);
    }
}

#[test]
fn transfer_rejects_a_declared_output_count_mismatch() {
    let mut transfer = Transfer::normal();
    transfer.declared_states = Some(Vec::new());
    transfer.rejects_at(0);
}

#[test]
fn hash_chain_borrow_rejects_bad_signatures_and_witness_lengths() {
    let (key, public_key) = demo_keys(0xcc);
    let next_guard = [0x42; 32];
    let mut transfer = Transfer::borrowed(1);
    transfer.borrow_policy(BORROW_HASH_CHAIN, chain_guard(&next_guard, &key));
    transfer.outputs[0].insert("borrow_guard".into(), next_guard.to_vec().into());

    let mut witness = vec![PATH_BORROW];
    witness.extend(next_guard);
    witness.extend(public_key);
    witness.extend([0u8; 64]);
    witness.push(SIG_HASH_ALL.to_u8());
    transfer.inputs[0].authorization = Authorization::Raw(witness.clone());
    transfer.rejects_at(0);
    witness.pop();
    transfer.inputs[0].authorization = Authorization::Raw(witness);
    transfer.rejects_at(0);

    let mut transfer = Transfer::borrowed(0);
    transfer.borrow_policy(BORROW_HASH_CHAIN, chain_guard(&next_guard, &key));
    transfer.outputs[0].insert("borrow_guard".into(), next_guard.to_vec().into());
    transfer.inputs[0].authorization = Authorization::HashChain { next_guard, key };
    transfer.rejects_at(0);
}

#[test]
fn transfer_accepts_every_supported_input_output_shape() {
    for input_count in 1..=3 {
        for output_count in 1..=3 {
            let mut transfer = Transfer::normal();
            for index in 1..input_count {
                let (key, public_key) = demo_keys(0xaa + index as u8);
                transfer.inputs.push(Input {
                    state: token_state(&public_key, 100),
                    authorization: Authorization::Owner(key),
                });
            }
            let (_, public_key) = demo_keys(0xbb);
            let total = 100 * input_count as i64;
            transfer.outputs = (0..output_count)
                .map(|index| {
                    let amount = total / output_count as i64
                        + if index == 0 {
                            total % output_count as i64
                        } else {
                            0
                        };
                    token_state(&public_key, amount)
                })
                .collect();
            transfer.output_values = (0..output_count)
                .map(|index| {
                    let total = TOKEN_OUTPUT_SOMPI * input_count as u64;
                    total / output_count as u64
                        + if index == 0 {
                            total % output_count as u64
                        } else {
                            0
                        }
                })
                .collect();
            let transaction = transfer.build().unwrap();
            assert_eq!(transaction.inputs.len(), input_count);
            assert_eq!(transaction.outputs.len(), output_count);
        }
    }
}

#[test]
fn leader_and_borrowed_successor_use_covenant_positions() {
    let mut transfer = Transfer::borrowed(11);
    transfer.ordinary_prefix = true;
    transfer.build().unwrap();
}

#[test]
fn leader_and_delegator_entrypoints_reject_opposite_roles() {
    let mut transfer = Transfer::borrowed(11);
    transfer.inputs[0].authorization = Authorization::Owner(demo_keys(0xbb).0);
    transfer.entries = Some(vec!["transfer_delegator", "transfer_delegator"]);
    transfer.rejects_at(0);

    transfer.entries = Some(vec!["transfer", "transfer"]);
    transfer.rejects_at(1);
}

#[test]
fn delegate_cannot_authorize_continuation_outputs() {
    let mut transfer = Transfer::borrowed(11);
    transfer.output_bindings = Some(vec![
        CovenantBinding::new(0, covenant_id()),
        CovenantBinding::new(1, covenant_id()),
    ]);
    let (transaction, utxos) = transfer.signed_case().unwrap();
    // Inspect each input independently; the leader must not mask delegate failure.
    for input_index in [0, 1] {
        assert!(execute_input_with_covenants(&transaction, utxos.clone(), input_index).is_err());
    }
}

#[test]
fn continuation_rejects_missing_or_foreign_covenant_binding() {
    let transfer = Transfer::borrowed(11);
    for binding in [
        None,
        Some(CovenantBinding::new(0, Hash::from_bytes([0x22; 32]))),
    ] {
        let (mut transaction, utxos) = transfer.signed_case().unwrap();
        transaction.outputs[0].covenant = binding;
        // The threshold leader has no signature, so rejection cannot be a stale signature.
        assert!(execute_input_with_covenants(&transaction, utxos, 0).is_err());
    }
}

#[test]
fn continuation_rejects_an_uncommitted_program() {
    let transfer = Transfer::borrowed(11);
    let (mut transaction, utxos) = transfer.signed_case().unwrap();
    transaction.outputs[0].script_public_key = ScriptPublicKey::from_vec(0, vec![0x51]);
    assert!(execute_input_with_covenants(&transaction, utxos, 0).is_err());
}

#[test]
fn hash_chain_accepts_successive_fresh_links() {
    let (first_key, _) = demo_keys(0xcc);
    let (second_key, _) = demo_keys(0xdd);
    let final_guard = [0x42; 32];
    let middle_guard = chain_guard(&final_guard, &second_key);
    let initial_guard = chain_guard(&middle_guard, &first_key);
    let mut transfer = Transfer::borrowed(1);
    transfer.borrow_policy(BORROW_HASH_CHAIN, initial_guard);
    transfer.outputs[0].insert("borrow_guard".into(), middle_guard.to_vec().into());
    transfer.inputs[0].authorization = Authorization::HashChain {
        next_guard: middle_guard,
        key: first_key,
    };
    transfer.build().unwrap();

    transfer.inputs[0].state = transfer.outputs[0].clone();
    transfer.inputs[1].state = transfer.outputs[1].clone();
    transfer.outputs[0].insert("amount".into(), 202i64.into());
    transfer.outputs[1].insert("amount".into(), 98i64.into());
    transfer.outputs[0].insert("borrow_guard".into(), final_guard.to_vec().into());
    transfer.inputs[0].authorization = Authorization::HashChain {
        next_guard: final_guard,
        key: second_key,
    };
    transfer.build().unwrap();
}

#[test]
fn normal_owner_can_replace_borrow_policy() {
    let mut transfer = Transfer::normal();
    let (key, public_key) = demo_keys(0xcc);
    let final_guard = [0x42; 32];
    for (scheme, guard) in [
        (BORROW_DISABLED, [0x42; 32]),
        (BORROW_AMOUNT_THRESHOLD, [0; 32]),
        (BORROW_SCHNORR_SIGNATURE, public_key),
        (BORROW_HASH_CHAIN, chain_guard(&final_guard, &key)),
    ] {
        transfer.outputs[0].insert("borrow_scheme".into(), scheme.into());
        transfer.outputs[0].insert("borrow_guard".into(), guard.to_vec().into());
        transfer.build().unwrap();
    }
}

#[test]
fn zero_and_maximum_token_amounts_are_spendable() {
    for amount in [0i64, i64::MAX] {
        let mut transfer = Transfer::normal();
        transfer.inputs[0]
            .state
            .insert("amount".into(), amount.into());
        transfer.outputs[0].insert("amount".into(), amount.into());
        transfer.build().unwrap();
    }
}

#[test]
fn threshold_borrow_cannot_be_satisfied_at_maximum_threshold() {
    let mut transfer = Transfer::borrowed(11);
    let mut guard = [0u8; 32];
    guard[..8].copy_from_slice(&i64::MAX.to_le_bytes());
    transfer.borrow_policy(BORROW_AMOUNT_THRESHOLD, guard);
    transfer.rejects_at(0);
}

#[test]
fn owner_witnesses_require_exact_lengths_for_both_roles() {
    for scheme in 0..=OWNER_COVENANT_ID {
        for index in [0, 1] {
            let mut transfer = if index == 0 {
                Transfer::normal()
            } else {
                Transfer::borrowed(11)
            };
            transfer.owner_scheme(index, scheme);
            let (transaction, utxos) = transfer.signed_case().unwrap();
            let unsigned = MutableTransaction::with_entries(transaction, utxos);
            let valid = transfer.inputs[index]
                .authorization
                .witness(&unsigned, index, index == 0);
            let mut trailing = valid.clone();
            trailing.push(0);
            transfer.inputs[index].authorization = Authorization::Raw(trailing);
            transfer.rejects_at(index);
            // An empty covenant-ID delegate witness cannot be shortened.
            if !valid.is_empty() {
                transfer.inputs[index].authorization =
                    Authorization::Raw(valid[..valid.len() - 1].to_vec());
                transfer.rejects_at(index);
            }
        }
    }
}

#[test]
fn p2pkh_rejects_invalid_signatures_even_with_the_correct_public_key() {
    for scheme in [OWNER_P2PKH_SCHNORR, OWNER_P2PKH_ECDSA] {
        let mut transfer = Transfer::normal();
        transfer.owner_scheme(0, scheme);
        let (transaction, utxos) = transfer.signed_case().unwrap();
        let unsigned = MutableTransaction::with_entries(transaction, utxos);
        let mut witness = transfer.inputs[0].authorization.witness(&unsigned, 0, true);
        let signature_start = witness.len() - 65;
        witness[signature_start..signature_start + 64].fill(0);
        transfer.inputs[0].authorization = Authorization::Raw(witness);
        transfer.rejects_at(0);
    }
}

#[test]
fn p2sh_authority_index_is_unsigned() {
    let mut transfer = Transfer::normal();
    transfer.owner_scheme(0, OWNER_P2SH);
    transfer.inputs[0].authorization = Authorization::Raw(vec![PATH_NORMAL, 255]);
    let (mut transaction, mut utxos) = transfer.signed_case().unwrap();
    for index in 0..254 {
        transaction.inputs.insert(
            1,
            TxBuilder::transaction_input(demo_outpoint(4, index), Vec::new()),
        );
        utxos.insert(
            1,
            UtxoEntry::new(
                1_000,
                ScriptPublicKey::from_vec(0, vec![0x51]),
                1,
                false,
                None,
            ),
        );
    }
    execute_input_with_covenants(&transaction, utxos, 0).unwrap();
}

#[test]
fn covenant_id_authority_may_be_a_distinct_family() {
    let mut transfer = Transfer::normal();
    transfer.owner_scheme(0, OWNER_COVENANT_ID);
    let authority_id = Hash::from_bytes([0x22; 32]);
    transfer.inputs[0]
        .state
        .insert("owner".into(), authority_id.as_bytes().to_vec().into());
    transfer.authority = Some((
        UtxoEntry::new(
            1_000,
            ScriptPublicKey::from_vec(0, vec![0x51]),
            1,
            false,
            Some(authority_id),
        ),
        Vec::new(),
    ));
    transfer.build().unwrap();
}

#[test]
fn public_mint_preserves_kcc20_state_layout_and_transfer_abi() {
    let contract = &artifact().sil_abi.contracts["KCC20"];
    let fields: Vec<_> = contract
        .runtime_state
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    assert_eq!(
        fields,
        [
            "gen__kcc20_template",
            "amount",
            "owner",
            "owner_scheme",
            "borrow_scheme",
            "borrow_guard",
            "extension_commitment"
        ]
    );
    for (entry, params) in [
        ("transfer", vec!["next_states", "witness"]),
        ("transfer_delegator", vec!["witness"]),
    ] {
        let entry = &contract.entries[entry];
        assert_eq!(
            entry
                .params
                .iter()
                .map(|param| param.name.as_str())
                .collect::<Vec<_>>(),
            params,
        );
    }
}

#[test]
fn kcc20_dispatch_tags_match_spec_vectors() {
    // KCC-20's authoritative dispatch vectors.
    // KCC-1 section 6.1 uses BLAKE3(signature)[0:4], with records expanded by field type.
    let contract = &artifact().sil_abi.contracts["KCC20"];
    for (entry, signature, expected_tag) in [
        (
            "transfer",
            "transfer({int,byte[32],byte,byte,byte[32],byte[32]}[],byte[])",
            [0x79, 0xc7, 0x1c, 0x23],
        ),
        (
            "transfer_delegator",
            "transfer_delegator(byte[])",
            [0xfd, 0x3e, 0xf1, 0x4a],
        ),
    ] {
        let digest = blake3::hash(signature.as_bytes());
        assert_eq!(&digest.as_bytes()[..4], &expected_tag, "{entry} vector");
        assert_eq!(
            contract.entries[entry].dispatch_tag.as_bytes(),
            &expected_tag,
            "{entry} compiled dispatch tag",
        );
    }
}

#[test]
fn signature_schemes_accept_all_consensus_sighash_types() {
    for byte in [0x01, 0x02, 0x04, 0x81, 0x82, 0x84] {
        let hash_type = SigHashType::from_u8(byte).unwrap();
        for scheme in [OWNER_P2PK_SCHNORR, OWNER_P2PKH_SCHNORR, OWNER_P2PKH_ECDSA] {
            let mut transfer = Transfer::normal();
            transfer.owner_scheme(0, scheme);
            transfer.signature_hash_type = hash_type;
            transfer.build().unwrap();
        }
        let (key, public_key) = demo_keys(0xcc);
        let mut transfer = Transfer::borrowed(1);
        transfer.borrow_policy(BORROW_SCHNORR_SIGNATURE, public_key);
        transfer.inputs[0].authorization = Authorization::BorrowSignature(key);
        transfer.signature_hash_type = hash_type;
        transfer.build().unwrap();
    }
}

#[test]
fn p2sh_authority_must_also_execute_successfully() {
    let mut transfer = Transfer::normal();
    let (key, public_key) = demo_keys(0xcc);
    let redeem_script = ScriptBuilder::new()
        .add_data(&public_key)
        .unwrap()
        .add_op(kaspa_txscript::opcodes::codes::OpCheckSig)
        .unwrap()
        .drain();
    let script = pay_to_script_hash_script(&redeem_script);
    transfer.inputs[0]
        .state
        .insert("owner_scheme".into(), OWNER_P2SH.into());
    transfer.inputs[0]
        .state
        .insert("owner".into(), script.script()[2..34].to_vec().into());
    transfer.inputs[0].authorization = Authorization::Raw(vec![PATH_NORMAL, 1]);
    transfer.authority = Some((UtxoEntry::new(1_000, script, 1, false, None), Vec::new()));
    let (transaction, utxos) = transfer.signed_case().unwrap();
    let unsigned = MutableTransaction::with_entries(transaction, utxos.clone());
    let signature = sign_input(&unsigned, 1, &key);
    let args = ScriptBuilder::new().add_data(&signature).unwrap().drain();
    let mut transaction = unsigned.tx;
    transaction.inputs[1].signature_script = pay_to_script_hash_signature_script_with_flags(
        redeem_script.clone(),
        args,
        covenant_engine_flags(),
    )
    .unwrap();
    execute_transaction_with_covenants(&mut transaction, utxos.clone()).unwrap();

    let mut invalid_signature = signature;
    invalid_signature[..64].fill(0);
    let args = ScriptBuilder::new()
        .add_data(&invalid_signature)
        .unwrap()
        .drain();
    transaction.inputs[1].signature_script = pay_to_script_hash_signature_script_with_flags(
        redeem_script,
        args,
        covenant_engine_flags(),
    )
    .unwrap();
    let error = execute_transaction_with_covenants(&mut transaction, utxos).unwrap_err();
    assert!(
        matches!(error, BuilderError::InputScript { input_index: 1, .. }),
        "{error}"
    );
}
