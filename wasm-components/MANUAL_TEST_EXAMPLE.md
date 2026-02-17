# Manual Test Example (REST + Wasm Verification Component)

This guide runs the real attestation-service flow:

1. Build Wasm verifier components
2. Start `restful-as`
3. Register a Wasm component (`POST /component`)
4. Send an attestation request (`POST /attestation`) that references `component_id`

It includes both TDX and SNP examples.

## Prerequisites

- Run from repo root.
- Tools: `cargo`, `jq`, `curl`, `base64`.
- Network is required for TDX collateral fetch (unless already cached).

## 1) Build verifier components

Build TDX component and force output into root `target/`:

```bash
cargo build \
  --manifest-path wasm-components/Cargo.toml \
  -p tdx-verifier-component \
  --release \
  --target wasm32-wasip2 \
  --target-dir target
```

Build SNP component (this script writes to root `target/`):

```bash
bash wasm-components/snp-verifier-component/scripts/build-snp-wasm-component.sh
```

Expected artifacts:

- `target/wasm32-wasip2/release/tdx_verifier_component.wasm`
- `target/wasm32-wasip2/release/snp_verifier_component.wasm`

## 2) Start attestation-service (REST)

Create a local config so AS writes only under `/tmp`:

```bash
cat > /tmp/as-wasm-manual-config.json <<'JSON'
{
  "work_dir": "/tmp/as-wasm-manual",
  "rvps_config": {
    "type": "BuiltIn",
    "storage": {
      "type": "LocalFs",
      "file_path": "/tmp/as-wasm-manual/reference_values"
    }
  },
  "attestation_token_broker": {
    "policy_dir": "/tmp/as-wasm-manual/policies"
  },
  "wasm_component_registry": {
    "verify_component_signature": false,
    "component_cache_base_dir": "/tmp/as-wasm-manual/component-cache"
  }
}
JSON
```

Start RESTful AS (Terminal A):

```bash
RUST_LOG=info,restful_as=debug,attestation_service=info \
cargo run -p attestation-service \
  --no-default-features \
  --features "restful-bin,wasm-verification-component-driver" \
  --bin restful-as -- \
  --config-file /tmp/as-wasm-manual-config.json \
  --socket 127.0.0.1:8080
```

Use another terminal for requests (Terminal B).

## 3) Helper for URL-safe base64 without padding

```bash
b64url_file() {
  base64 -w0 "$1" | tr '+/' '-_' | tr -d '='
}
```

## 4) TDX flow (using `tdx_quote.bin`)

Use `tdx_quote_5.dat` sample but name it `tdx_quote.bin`:

```bash
cp deps/verifier/test_data/tdx_quote_5.dat /tmp/tdx_quote.bin
```

Register TDX Wasm component:

```bash
jq -n \
  --arg component "$(b64url_file target/wasm32-wasip2/release/tdx_verifier_component.wasm)" \
  '{component: $component}' > /tmp/register-tdx.json

curl -sS -X POST http://127.0.0.1:8080/component \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/register-tdx.json | tee /tmp/register-tdx-resp.json

TDX_COMPONENT_ID="$(jq -r '.component_id' /tmp/register-tdx-resp.json)"
echo "TDX_COMPONENT_ID=$TDX_COMPONENT_ID"
```

Build wrapped TDX evidence:

```bash
TDX_QUOTE_B64="$(base64 -w0 /tmp/tdx_quote.bin)"

jq -n \
  --arg component_id "$TDX_COMPONENT_ID" \
  --arg quote "$TDX_QUOTE_B64" \
  --arg pccs_url "${PCCS_URL:-}" \
  '{
     component_id: $component_id,
     evidence: { quote: $quote },
     tee_class: "cpu"
   } + (if $pccs_url == "" then {} else { pccs_url: $pccs_url } end)' \
  > /tmp/tdx-wasm-evidence-decoded.json
```

Build attestation request and call `/attestation`:

```bash
jq -n \
  --arg evidence "$(b64url_file /tmp/tdx-wasm-evidence-decoded.json)" \
  '{
     verification_requests: [{
       tee: "tdx",
       verifier: "wasm-verification-component",
       evidence: $evidence
     }],
     policy_ids: ["default"]
   }' > /tmp/attest-tdx.json

curl -sS -X POST http://127.0.0.1:8080/attestation \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/attest-tdx.json | tee /tmp/attest-tdx-token.txt
```

## 5) SNP flow

Register SNP Wasm component:

```bash
jq -n \
  --arg component "$(b64url_file target/wasm32-wasip2/release/snp_verifier_component.wasm)" \
  '{component: $component}' > /tmp/register-snp.json

curl -sS -X POST http://127.0.0.1:8080/component \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/register-snp.json | tee /tmp/register-snp-resp.json

SNP_COMPONENT_ID="$(jq -r '.component_id' /tmp/register-snp-resp.json)"
echo "SNP_COMPONENT_ID=$SNP_COMPONENT_ID"
```

Wrap SNP evidence from sample JSON:

```bash
jq -n \
  --arg component_id "$SNP_COMPONENT_ID" \
  --slurpfile ev attestation-service/tests/e2e/evidence.json \
  '{
     component_id: $component_id,
     evidence: $ev[0],
     tee_class: "cpu"
   }' > /tmp/snp-wasm-evidence-decoded.json
```

Build attestation request and call `/attestation`:

```bash
jq -n \
  --arg evidence "$(b64url_file /tmp/snp-wasm-evidence-decoded.json)" \
  '{
     verification_requests: [{
       tee: "snp",
       verifier: "wasm-verification-component",
       evidence: $evidence
     }],
     policy_ids: ["default"]
   }' > /tmp/attest-snp.json

curl -sS -X POST http://127.0.0.1:8080/attestation \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/attest-snp.json | tee /tmp/attest-snp-token.txt
```

## 6) Notes

- `component_id` is stable for identical Wasm bytes. Re-registering the same component returns the same ID.
- Cache is host-managed under `component_cache_base_dir/<component_id>/...`.
