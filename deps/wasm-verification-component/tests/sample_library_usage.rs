use std::path::PathBuf;
use wasm_verification_component::{VerifyOptions, WasmVerificationComponent};

fn repo_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or("failed to determine repo root")?
        .to_path_buf())
}

#[test]
fn sample_library_usage_with_snp_json_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = repo_root()?;

    let component_path = repo_root.join("target/wasm32-wasip2/release/snp_verifier_component.wasm");
    let evidence_path = repo_root.join("snp_evidence.json");

    if !component_path.exists() {
        eprintln!(
            "skipping sample test: missing {} (build with `bash wasm-components/snp-verifier-component/scripts/build-snp-wasm-component.sh`)",
            component_path.display()
        );
        return Ok(());
    }

    if !evidence_path.exists() {
        eprintln!("skipping sample test: missing {}", evidence_path.display());
        return Ok(());
    }

    let verifier = WasmVerificationComponent::new()?;
    let options = VerifyOptions {
        cache_dir: repo_root.join(".wasm-verification-component-sample-test-cache"),
        pccs_url: None,
    };

    let result = verifier.verify_paths(component_path, evidence_path, &options)?;

    assert_eq!(result["reported_tcb_snp"], 23);
    assert_eq!(result["reported_tcb_bootloader"], 10);
    assert!(
        result
            .get("measurement")
            .and_then(|v| v.as_str())
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "measurement claim must be present"
    );

    Ok(())
}

#[test]
fn sample_library_usage_with_tdx_quote() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = repo_root()?;
    let component_path = repo_root.join("target/wasm32-wasip2/release/tdx_verifier_component.wasm");
    let evidence_path = repo_root.join("tdx_quote.bin");

    if !component_path.exists() {
        eprintln!(
            "skipping sample test: missing {} (build with `cargo build --manifest-path wasm-components/Cargo.toml -p tdx-verifier-component --target wasm32-wasip2 --release`)",
            component_path.display()
        );
        return Ok(());
    }

    if !evidence_path.exists() {
        eprintln!("skipping sample test: missing {}", evidence_path.display());
        return Ok(());
    }

    let verifier = WasmVerificationComponent::new()?;
    let options = VerifyOptions {
        cache_dir: repo_root.join(".wasm-verification-component-sample-tdx-cache"),
        pccs_url: std::env::var("WASM_VERIFICATION_COMPONENT_PCCS_URL").ok(),
    };

    let result = verifier.verify_paths(component_path, evidence_path, &options)?;

    assert!(result.get("quote").is_some(), "quote claim must be present");
    assert!(
        result
            .get("tcb_status")
            .and_then(|v| v.as_str())
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "tcb_status claim must be present"
    );

    Ok(())
}
