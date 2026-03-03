# Manual Test Example (Docker + Existing Compose + gRPC + Wasm Verification Component)

This guide runs the same end-to-end flow as `MANUAL_TEST_EXAMPLE.md`, but using Docker and the existing repo `docker-compose.yml`:

1. Build TDX/SNP Wasm verifier components
2. Start `grpc-as` from the existing compose stack
3. Register Wasm components via gRPC `RegisterComponent`
4. Send attestation requests via gRPC `AttestationEvaluate`

It includes both TDX and SNP examples.

## Prerequisites

- Run from repo root.
- Tools on host: `docker`, `docker compose`, `jq`, `base64`.
- `sudo` may be required for Docker commands, depending on your setup.
- This uses only existing Dockerfiles and `docker-compose.yml` (no new compose file).

## 1) Build verifier components (Docker)

Build your TDX and SNP Wasm components or use the availible ones at the following path:

- `deps/verifier/src/wasm_verification_component/test_assets/test_data/tdx_verifier_component.wasm`
- `deps/verifier/src/wasm_verification_component/test_assets/test_data/snp_verifier_component.wasm`

## 2) Start AS using existing compose files

The compose file starts `grpc-as`. Rebuild `as` with wasm verification component driver enabled:

```bash
docker compose down as rvps
docker compose up -d setup
docker compose build --no-cache --build-arg VERIFIER='wasm-verification-component-driver' as
docker compose up -d rvps as
docker compose logs --tail=120 as
```

Confirm the service is up on `50004`:

```bash
docker compose ps
docker compose port as 50004
```

## 3) Helpers

```bash
b64url_file() {
  base64 -w0 "$1" | tr '+/' '-_' | tr -d '=\n'
}

grpcurl_docker() {
  docker run --rm -i --network host \
    -v "$PWD:/work" \
    fullstorydev/grpcurl:latest \
    -plaintext \
    -import-path /work/protos \
    -proto /work/protos/attestation.proto \
    -d @ 127.0.0.1:50004 "$1"
}
```

## 4) TDX flow

Prepare sample quote:

```bash
cp deps/verifier/test_data/tdx_quote.bin /tmp/tdx_quote.bin
```

Register TDX Wasm component:

```bash
# Avoid "Argument list too long" by streaming into jq
b64url_file deps/verifier/src/wasm_verification_component/test_assets/test_data/tdx_verifier_component.wasm \
  | jq -Rs '{component: .}' > /tmp/register-tdx-grpc.json

grpcurl_docker attestation.AttestationService/RegisterComponent \
  < /tmp/register-tdx-grpc.json | tee /tmp/register-tdx-grpc-resp.json

TDX_COMPONENT_ID="$(jq -r '.componentId // .component_id' /tmp/register-tdx-grpc-resp.json)"
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

Call `AttestationEvaluate`:

```bash
jq -n \
  --arg evidence "$(b64url_file /tmp/tdx-wasm-evidence-decoded.json)" \
  '{
     verificationRequests: [{
       tee: "tdx",
       verifier: "wasm-verification-component",
       evidence: $evidence
     }],
     policyIds: ["default"]
   }' > /tmp/attest-tdx-grpc.json

grpcurl_docker attestation.AttestationService/AttestationEvaluate \
  < /tmp/attest-tdx-grpc.json | tee /tmp/attest-tdx-grpc-resp.json

jq -r '.attestationToken // .attestation_token' /tmp/attest-tdx-grpc-resp.json > /tmp/attest-tdx-token.txt
```

## 5) SNP flow

Register SNP Wasm component:

```bash
b64url_file deps/verifier/src/wasm_verification_component/test_assets/test_data/snp_verifier_component.wasm \
  | jq -Rs '{component: .}' > /tmp/register-snp-grpc.json

grpcurl_docker attestation.AttestationService/RegisterComponent \
  < /tmp/register-snp-grpc.json | tee /tmp/register-snp-grpc-resp.json

SNP_COMPONENT_ID="$(jq -r '.componentId // .component_id' /tmp/register-snp-grpc-resp.json)"
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

Call `AttestationEvaluate`:

```bash
jq -n \
  --arg evidence "$(b64url_file /tmp/snp-wasm-evidence-decoded.json)" \
  '{
     verificationRequests: [{
       tee: "snp",
       verifier: "wasm-verification-component",
       evidence: $evidence
     }],
     policyIds: ["default"]
   }' > /tmp/attest-snp-grpc.json

grpcurl_docker attestation.AttestationService/AttestationEvaluate \
  < /tmp/attest-snp-grpc.json | tee /tmp/attest-snp-grpc-resp.json

jq -r '.attestationToken // .attestation_token' /tmp/attest-snp-grpc-resp.json > /tmp/attest-snp-token.txt
```

## 6) Stop services

```bash
docker compose down
```

## Troubleshooting

- `connection refused` to `127.0.0.1:50004`:
  - `as` is not up or crashed. Run `docker compose ps` and `docker compose logs --tail=200 as`.
- `Unimplemented` on `RegisterComponent`:
  - You are running an older `as` image. Rebuild and restart `as`.
- `feature wasm-verification-component-driver is not enabled`:
  - Rebuild with `--build-arg VERIFIER='wasm-verification-component-driver'`.
- `libsgx_dcap_quoteverify.so.1` missing:
  - Do not pass comma-separated feature list in `VERIFIER`; use only `wasm-verification-component-driver` for this flow.
