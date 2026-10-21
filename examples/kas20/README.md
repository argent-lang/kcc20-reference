# KAS20

KAS20, symbol KAS, enables applications built for KCC-20 tokens to compose with
KAS using the same code and state structure. Native KAS is held in the UTXO
value; KAS20 wraps it in the token state, ownership rules, and transfer
interface those applications already support.

For example, a DEX can pair KAS with other tokens using its existing KCC-20
pool logic. Each KAS20 output holds its own backing KAS, one-to-one. Minting
wraps KAS; burning releases it.

This example implements KAS20 in Argent and runs locally with synthetic funding.
Its Rust crate reuses the reference's demo helpers through a path dependency.

## Contracts and composition

[`token.ag`](contracts/token.ag) builds on the reference's
[KCC-20 state and authorization](../../contracts/kcc20.ag), including
covenant-ID ownership and borrowed receive. KAS20 uses the same eight decimal
places as KAS, with one token base unit per sompi. Minting and transfers enforce
exact backing on every token output:

```text
value in sompi = amount in token base units
```

Minting is permissionless and has no token supply cap: every new KAS20 must be
funded with KAS, so supply is constrained by the KAS available to wrap.
[`minter.ag`](contracts/minter.ag) supports public minting and permissionless
creation of additional minters in the same token family. The minter's operational KAS is separate from
token backing; its owner can rebalance it or retire a minter while preserving
another. [`app.ag`](contracts/app.ag) creates one minter at genesis, with no
pre-minted tokens.

`burn` consumes a whole token output with owner authorization and releases its
backing KAS to the owner's chosen payout, allowing a portion to cover fees. Borrow
authorization does not permit burning. Split first to burn part of an output,
or merge first to burn several together.

Recognizing one deployment per network as the shared KCC-20 representation of
KAS would let applications converge on the same asset and liquidity. Anyone
could mint into that shared token family; a separate deployment would have a
different covenant ID and remain a distinct asset. This is a proposed ecosystem
convention; this example does not designate a canonical deployment.

## Run and debug

From `examples/kas20/`:

```sh
cargo run --locked -- build
cargo run --locked -- demo
```

The offline demo deploys KAS20, mints one KAS20 each to Bob and Alice, transfers
Alice's KAS20 to Bob through borrowed receive, and burns Bob's two KAS20. It also
splits and rebalances the minter. It uses deterministic test keys and submits
no transactions to a node.

`build/kas20-demo/` contains the compiled contracts, genesis transaction, initial
state, Argent genesis proof, and demo transactions.

To run the same demo as a test:

```sh
cargo test --locked --bin kas20 tests::run_demo -- --exact --nocapture
```

In VS Code with CodeLLDB, click **Debug** above `run_demo` in
[`src/main.rs`](src/main.rs). Breakpoints at
`bootstrap.clone().compose(&bundle)` and `argent.verify_argent(id)` show proof
construction and verification. The test writes the same demo artifacts.

## Fixtures and checks

```sh
cargo run --locked -- fixtures
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Regeneration updates only KAS20 artifacts in [`fixtures`](fixtures/): the token
descriptor, compiled artifact, manifest, and SIL. Tests cover backing, owner and borrow authorization,
minter lifecycle, deposit rebalancing, burning, and positive demo output values.
