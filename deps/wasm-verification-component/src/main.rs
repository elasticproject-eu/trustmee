use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use wasm_verification_component::{VerifyOptions, WasmVerificationComponent};

#[derive(Parser, Debug)]
#[command(name = "wasm-verification-component")]
#[command(about = "Minimal evidence-only attestation verifier using a Wasm component")]
struct Args {
    /// Path to verifier component (.wasm)
    #[arg(long)]
    component: PathBuf,

    /// Path to evidence input file
    #[arg(long)]
    evidence: PathBuf,

    /// Cache directory pre-opened to the component as `cache/`
    #[arg(long, default_value = ".wasm-verification-component-cache")]
    cache_dir: PathBuf,

    /// Optional PCCS URL used by TDX verifier components
    #[arg(long)]
    pccs_url: Option<String>,

    /// Print compact one-line JSON
    #[arg(long)]
    compact: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let verifier = WasmVerificationComponent::new()?;

    let options = VerifyOptions {
        cache_dir: args.cache_dir,
        pccs_url: args.pccs_url,
    };

    let result = verifier.verify_paths(&args.component, &args.evidence, &options)?;
    if args.compact {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(())
}
