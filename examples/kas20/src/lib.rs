//! KAS-backed KCC20 token and offline examples.

use std::{collections::BTreeMap, fs, path::Path};

use argent::{CompiledAppBundle, build_file_bundle};
use argent_runtime::{ArtifactValue, state};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type ActorState = BTreeMap<String, ArtifactValue>;

pub const SOMPI_PER_KAS: i64 = 100_000_000;
pub const DECIMALS: u8 = 8;
// Operational value chosen for the demo minter; never added to token amounts.
pub const MINTER_VALUE: u64 = 1_000_000;
pub const GENESIS_GROUP: &str = "launch::kas20";

pub fn compile(output: impl AsRef<Path>) -> Result<CompiledAppBundle> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize()?;
    let output = output.as_ref();
    let compiled = build_file_bundle(root.join("contracts/app.ag"), output)?;
    // Argent records source paths relative to the process's working directory.
    // Keep generated source locations relative to this crate, including the reference import.
    let repository = root.join("../..").canonicalize()?;
    let normalize = |value: &mut serde_json::Value| -> Result<()> {
        let source = Path::new(value.as_str().ok_or("invalid source path")?).canonicalize()?;
        let relative = match source.strip_prefix(&root) {
            Ok(relative) => relative.to_path_buf(),
            Err(_) => Path::new("../..").join(source.strip_prefix(&repository)?),
        };
        *value = relative.to_string_lossy().replace('\\', "/").into();
        Ok(())
    };
    for name in ["artifact.json", "manifest.json"] {
        let file = output.join(name);
        let mut document: serde_json::Value = serde_json::from_slice(&fs::read(&file)?)?;
        normalize(&mut document["root"])?;
        for module in document["modules"]
            .as_array_mut()
            .ok_or("missing source modules")?
        {
            normalize(module)?;
        }
        fs::write(file, serde_json::to_string_pretty(&document)? + "\n")?;
    }
    Ok(compiled)
}

pub fn token_state(owner: &[u8; 32], amount: i64) -> ActorState {
    state! {
        amount: amount,
        owner: owner.to_vec(),
        owner_scheme: 0u8,
        borrow_scheme: 0u8,
        borrow_guard: vec![0u8; 32],
        extension_commitment: vec![0u8; 32]
    }
}

pub fn minter_state(owner: &[u8; 32]) -> ActorState {
    state! { owner: owner.to_vec() }
}

pub fn backed_value(amount: i64) -> Result<u64> {
    Ok(u64::try_from(amount)?)
}
