use argent::build_file;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let artifact = build_file(
        root.join("contracts/public_mint.ag"),
        root.join("fixtures/public-mint"),
    )?;
    println!("{} (fixtures/public-mint)", artifact.app);
    for (name, contract) in &artifact.sil_abi.contracts {
        println!("  {name}: {} bytes", contract.compiled.bytecode.len());
    }
    Ok(())
}
