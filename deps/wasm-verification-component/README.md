# wasm-verification-component

Minimal evidence-only attestation verifier crate.

It accepts:
- attestation evidence bytes
- a verifier Wasm component (`TrustMee:verifier` WIT)

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

Build your TDX and SNP Wasm components or use the availible ones at the following path:

- `deps/wasm-verification-component/test_data/tdx_verifier_component.wasm`
- `deps/wasm-verification-component/test_data/snp_verifier_component.wasm`

## Test with the sample evidence files

```bash
# 1) TDX quote evidence (needs Intel PCS connectivity)
cargo run -p wasm-verification-component -- \
  --component deps/wasm-verification-component/test_data/tdx_verifier_component.wasm \
  --evidence deps/wasm-verification-component/test_data/tdx_quote.bin \
  --cache-dir .wasm-verification-component-tdx-cache \
  --compact

# 2) SNP JSON evidence (works offline because cert chain is embedded)
cargo run -p wasm-verification-component -- \
  --component deps/wasm-verification-component/test_data/snp_verifier_component.wasm \
  --evidence deps/wasm-verification-component/test_data/snp_evidence.json \
  --cache-dir .wasm-verification-component-snp-cache \
  --compact
```

## Sample library test

```bash
cargo test -p wasm-verification-component --test sample_library_usage -- --nocapture
```
