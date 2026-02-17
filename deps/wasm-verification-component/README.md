# wasm-verification-component

Minimal evidence-only attestation verifier crate.

It accepts:
- attestation evidence bytes
- a verifier Wasm component (`trustee:verifier` WIT)

It returns:
- attestation result JSON from the component

No reference value and policy checking.

## CLI usage

```bash
cargo run -p wasm-verification-component -- \
  --component <path-to-component.wasm> \
  --evidence <path-to-evidence-file> \
  --cache-dir <cache-dir> \
  --compact
```

## Build verifier components

```bash
cargo build --manifest-path wasm-components/Cargo.toml \
  -p tdx-verifier-component \
  --target wasm32-wasip2 \
  --release
```

For `snp-verifier-component`, use the builder colocated with the SNP wasm verification component:

```bash
# from repo root
bash wasm-components/snp-verifier-component/scripts/build-snp-wasm-component.sh
```

## Test with the three sample evidence files

```bash
# 1) TDX quote evidence (needs Intel PCS connectivity)
cargo run -p wasm-verification-component -- \
  --component target/wasm32-wasip2/release/tdx_verifier_component.wasm \
  --evidence tdx_quote.bin \
  --cache-dir .wasm-verification-component-tdx-cache \
  --compact

# 2) SNP JSON evidence (works offline because cert chain is embedded)
cargo run -p wasm-verification-component -- \
  --component target/wasm32-wasip2/release/snp_verifier_component.wasm \
  --evidence snp_evidence.json \
  --cache-dir .wasm-verification-component-snp-cache \
  --compact
```

## Sample library test

```bash
cargo test -p wasm-verification-component --test sample_library_usage -- --nocapture
```

## Use from another repo

Add dependency:

```toml
[dependencies]
wasm-verification-component = { path = "/path/to/trustee/deps/wasm-verification-component" }
```
