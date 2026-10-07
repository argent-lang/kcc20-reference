# KCC20 reference

[KCC20](https://github.com/kaspanet/kccs/blob/main/kcc-0020.md) defines a
fungible-token covenant convention for Kaspa: shared token state, transfer
entrypoints, owner authorization, borrowed receive, and program artifacts.
It builds on [KCC1](https://github.com/kaspanet/kccs/blob/main/kcc-0001.md) for
covenant structure and encoding and
[KCC2](https://github.com/kaspanet/kccs/blob/main/kcc-0002.md) for authority
schemes. Those specifications define the conventions; this README describes
this reference implementation.

The repository implements the `KCC20` actor in Argent and includes a
`KCC20PublicMint` app that adds permissionless issuance and zero-token receiving
UTXOs, with offline examples and contract tests.

## KCC20 actor

[contracts/kcc20.ag](contracts/kcc20.ag) implements the standard
[KCC20 state](https://github.com/kaspanet/kccs/blob/main/kcc-0020.md#1-state)
and [transfer interface](https://github.com/kaspanet/kccs/blob/main/kcc-0020.md#2-transfer-interface):

```text
transfer(KCC20State[] next_states, byte[] witness)
transfer_delegator(byte[] witness)
```

This reference supports one to three token inputs and one to three token
outputs. It supports all five
[standard owner schemes](https://github.com/kaspanet/kccs/blob/main/kcc-0002.md#21-authority-schemes)
and all four
[borrow scheme IDs](https://github.com/kaspanet/kccs/blob/main/kcc-0020.md#5-borrowed-receive).
See those specifications for scheme definitions and witness layouts.

Transfers preserve the total token amount and shared `extension_commitment`.
Amounts are non-negative integer base units; totals must fit within
`2^63 - 1`. The extension commitment is opaque to this actor, including zero.

Borrowed receive lets a sender pay into an existing recipient UTXO under its
borrow policy, without the recipient's owner authorization. The borrowed
successor preserves ownership and cannot lose KAS; the other inputs still
require their owners' authorization.

## Reference app

[contracts/public_mint.ag](contracts/public_mint.ag) defines `KCC20PublicMint`,
which combines the `KCC20` transfer actor with two supporting actors:
`PublicMint` for issuance and `TokenSeed` for creating receiving UTXOs.

### Minting: PublicMint

`PublicMint` tracks the remaining issuance allowance, a fixed per-mint limit,
a Schnorr deposit owner, and a fixed extension commitment. It provides:

- **Permissionless minting.** `mint(recipient_state)` issues a caller-chosen
  positive amount within both the per-mint limit and remaining allowance. It
  creates one token output and recreates the minter with the reduced allowance
  and unchanged KAS deposit. The caller chooses the recipient's owner and
  supported borrow policy, funds the new output and fee, and must use the
  minter's extension commitment.
- **Allowance splitting.** Anyone can call `split(take, new_owner)` to move a
  positive allowance of up to half the remaining amount into a second minter.
  Both retain the per-mint limit and extension commitment, preserving the total
  allowance. The original keeps its owner and KAS deposit; the caller chooses
  the second minter's deposit owner and funds its deposit.
- **Exhausted deposit reclaim.** `reclaim(owner_signature)` releases the KAS
  deposit once the allowance reaches zero, without creating a minter successor.
- **Allowance return.** `reclaim_into()` combines a retiring minter's allowance
  with a surviving minter that has the same per-mint limit and extension
  commitment. The survivor keeps its owner and KAS deposit. The retiring minter
  authorizes releasing its deposit through `reclaim_delegator(owner_signature)`;
  the survivor needs no signature.

The deposit owner authorizes reclaim with a transaction signature. The contract
does not fix a payout address. Minting and splitting require no deposit-owner
signature.

### Receiving UTXOs: TokenSeed

[contracts/token_seed.ag](contracts/token_seed.ag) defines `TokenSeed`. Each
seed stores a Schnorr deposit owner and a fixed extension commitment. It provides:

- **Permissionless creation.** `create(recipient_state)` creates a zero-token
  UTXO with the caller's chosen owner and supported borrow policy, using the
  seed's extension commitment. The caller funds the recipient's KAS deposit;
  the seed is recreated with unchanged state and KAS.
- **Seed splitting.** Anyone can call `split(new_owner)` to create another seed
  with the same extension commitment. The original keeps its state and deposit;
  the caller chooses the new seed's deposit owner and funds its deposit.
- **Deposit reclaim with a surviving seed.** `reclaim()` consumes a retiring
  seed with the same extension commitment and preserves the surviving seed's
  state and deposit. The retiring seed uses `reclaim_delegator(owner_signature)`;
  the survivor needs no signature. Every seed transition leaves at least one
  seed alive, so a lone seed cannot reclaim its deposit.

### Deployment and genesis

Deploy the token by creating its initial minter and seed UTXOs in a genesis
transaction. This transaction establishes the token's covenant ID and initial
issuance allowance. For this single-minter deployment, its genesis output group
should contain:

- **One `PublicMint`** with the advertised supply as its initial `remaining`
  allowance, plus the chosen per-mint limit, deposit owner, and extension
  commitment.
- **At least one `TokenSeed`** with the same extension commitment, so callers
  can create receiving UTXOs in this token family.
- **No pre-minted token balances.** Tokens are issued from the minter's allowance
  through `mint()`.

Create the minter and seed outputs together in the same genesis group of that
transaction so they share a covenant ID. Inspect the transaction's complete
genesis group to verify the advertised supply against all minter allowances
and token balances, and confirm that the seeds are present.

Seeds must be created in the token's genesis transaction. They can later split
to create more seeds within the same family, and remain usable after all
minters are exhausted or reclaimed. A new genesis transaction creates a
different covenant ID and cannot add a seed to this family.

## Examples

```sh
cargo run --locked --bin kcc20
cargo run --locked --bin kcc20 -- hash-chain
cargo run --locked --bin kcc20 -- mint
```

These demonstrate threshold borrowing (the default), successive hash-chain
borrows, and public minting. They execute locally with test data and do not
submit transactions to a network.

## Tests and scope

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Transfer tests encode transactions directly and execute them in the
covenant-enabled VM using the complete public-mint app. This lets malformed
cardinalities, role selections, witnesses, and continuations reach the contract
without being rejected by a transaction builder first. The suite covers each
owner scheme as leader and delegate, all borrow schemes, all supported
input/output shapes, authorization failures, conservation, state preservation,
and integer boundaries. Output scheme validation covers all 256 byte values.

ABI regression tests pin state field order, the standard transfer parameters,
and the KCC1 dispatch tags.

Conformance tests use the KCC-20 vector snapshot in
`fixtures/kcc20/conformance.json`. They compare ABI, encoding, and hash vectors
byte for byte and execute transfer and borrowed-receive cases in the VM.
The vectors' placeholder signing keys and signatures are replaced with real
ones for VM execution; related key commitments are recomputed. Run them with:

```sh
cargo test --locked --all-targets conformance_ -- --nocapture
```

The public-mint tests cover local genesis, successive issuance and transfer,
caller-selected amounts and borrow guards, fixed extension commitments, exhaustion,
integer boundaries, altered states, output shape, and preservation of
the minter's sompi.

Three initial lifecycle tests cover minter split, mint, and allowance return;
exhausted deposit reclaim; and seed split, zero-token creation, borrowed receive,
and reclaim with a surviving seed. They include a few basic rejection checks;
the split and reclaim entrypoints do not yet have a full conformance suite.

These offline tests do not exercise network submission or wallet
synchronization, and are not an independent security audit.

## KCC20 artifact

[fixtures/public-mint/kcc20.json](fixtures/public-mint/kcc20.json) describes this
token's KCC20 configuration: its transfer and delegator entrypoints, supported
owner-scheme bytes, and maximum token inputs and outputs per transfer.

Its `program.artifact` points to the sibling `artifact.json`, which provides the
compiled contracts, state layouts, and ABI. Clients use both files to construct
transactions.

## Artifacts

The examples compile the app into `build/public-mint/`. Use
`build/public-mint/artifact.json` to construct its transactions.

The generated SIL, artifact, and manifest are also tracked in
`fixtures/public-mint/` so contract and compiler changes can be reviewed in Git.
Temporary build output stays in the ignored `build/` directory. Regenerate the
pinned fixtures with:

```sh
cargo run --locked --example build_contracts
```

## Files

- [contracts/kcc20.ag](contracts/kcc20.ag): token state, authorization schemes, and transfer actor.
- [contracts/public_mint.ag](contracts/public_mint.ag): public-mint app with minter split and reclaim.
- [contracts/token_seed.ag](contracts/token_seed.ag): zero-token creation, seed split and reclaim actor.
- [src/bin/kcc20/main.rs](src/bin/kcc20/main.rs): threshold-borrow example.
- [src/bin/kcc20/chain_borrow.rs](src/bin/kcc20/chain_borrow.rs): two successive hash-chain borrowed receives.
- [src/bin/kcc20/public_mint.rs](src/bin/kcc20/public_mint.rs): local launch, mint, and transfer example.
- [src/bin/kcc20/public_mint/tests.rs](src/bin/kcc20/public_mint/tests.rs): issuance tests.
- [src/bin/kcc20/public_mint/tests/lifecycle.rs](src/bin/kcc20/public_mint/tests/lifecycle.rs): initial minter and seeder lifecycle tests.
- [src/bin/kcc20/support.rs](src/bin/kcc20/support.rs): offline keys and transaction signing.
- [src/bin/kcc20/tests.rs](src/bin/kcc20/tests.rs): contract and ABI tests.
- [src/bin/kcc20/tests/conformance_vectors.rs](src/bin/kcc20/tests/conformance_vectors.rs): spec vector encoding, hash, and VM tests.
- [examples/build_contracts.rs](examples/build_contracts.rs): fixture regeneration.
- [fixtures/public-mint/kcc20.json](fixtures/public-mint/kcc20.json): concrete reference artifact.
