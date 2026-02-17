# CoCo AS Configuration File

The Confidential Containers KBS properties can be configured through a
JSON-formatted configuration file.

## Configurable Properties

The following sections list the CoCo AS properties which can be set through the
configuration file.

### Global Properties

The following properties can be set globally, i.e. not under any configuration
section:

| Property                   | Type                        | Description                                         | Required | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|---------|
| `work_dir`                 | String                      | The location for Attestation Service to store data. | False      | Firstly try to read from ENV `AS_WORK_DIR`. If not any, use `/opt/confidential-containers/attestation-service`       |
| `rvps_config`              | [RVPSConfiguration][2]      | RVPS configuration                                  | False      | -       |
| `attestation_token_broker` | [AttestationTokenBroker][1]  | Attestation result token configuration.            | False      | -       |
| `verifier_config`          | [VerifierConfiguration][3]  | Optional configuration for verifier drivers.        | False      | -       |
| `wasm_component_registry`  | [WasmComponentRegistry][4]  | Optional config for wasm component registration and cache layout. | False | defaults |

[1]: #attestationtokenbroker
[2]: #rvps-configuration
[3]: #verifier-configuration
[4]: #wasm-component-registry

#### AttestationTokenBroker

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `developer_name`  | String               | The developer name to be used as part of the Verifier ID in the EAR | No       |`https://confidentialcontainers.org`|
| `build_name`  | String                  | The build name to be used as part of the Verifier ID in the EAR         | No       | Automatically generated from Cargo package and AS version|
| `profile_name`  | String                  | The Profile that describes the EAR token         | No       |tag:github.com,2024:confidential-containers/Trustee`|
| `policy_dir`  | String                  | The path to the work directory that contains policies to provision the tokens.        | No       |`/opt/confidential-containers/attestation-service/token/policies`|
| `signer`       | [TokenSignerConfig][1]  | Signing material of the attestation result token.    | No       | None       |

[1]: #tokensignerconfig

#### TokenSignerConfig

This section is **optional**. When omitted, a new EC key pair is generated and used.

| Property       | Type    | Description                                             | Required | Default |
|----------------|---------|---------------------------------------------------------|----------|---------|
| `key_path`     | String  | EC Key Pair file (PEM format) path.                     | Yes      | -       |
| `cert_url`     | String  | EC Public Key certificate chain (PEM format) URL.       | No       | -       |
| `cert_path`    | String  | EC Public Key certificate chain (PEM format) file path. | No       | -       |

#### RVPS Configuration

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `type`         | String                  | It can be either `BuiltIn` (Built-In RVPS) or `GrpcRemote` (connect to a remote gRPC RVPS) | No       | `BuiltIn` |

##### BuiltIn RVPS

If `type` is set to `BuiltIn`, the following extra properties can be set

| Property       | Type                    | Description                                                           | Required | Default  |
|----------------|-------------------------|-----------------------------------------------------------------------|----------|----------|
| `storage`   | ReferenceValueStorageConfig | Configuration of storage for reference values (`LocalFs` or `LocalJson`)       | No       | `LocalFs`|

`ReferenceValueStorageConfig` can contain either a `LocalFs` configuration or a `LocalJson` configuration.

For `LocalFs`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the directory storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values`|

For `LocalJson`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the file that storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values.json`|

##### Remote RVPS

If `type` is set to `GrpcRemote`, the following extra properties can be set

| Property       | Type                    | Description                             | Required | Default          |
|----------------|-------------------------|-----------------------------------------|----------|------------------|
| `address`      | String                  | Remote address of the RVPS server       | No       | `127.0.0.1:50003`|

#### Verifier Configuration

`verifier_config` is optional.

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `tpm_verifier` | Object                  | TPM verifier configuration                            | No       | -       |
| `nvidia_verifier` | Object               | NVIDIA verifier configuration                         | No       | -       |

For `wasm-verification-component`, no `verifier_config` is required. Register components via the component registration API and reference them by `component_id` in attestation requests.

#### Wasm Component Registry

`wasm_component_registry` is optional.

| Property                     | Type    | Description                                                             | Required | Default |
|-----------------------------|---------|-------------------------------------------------------------------------|----------|---------|
| `verify_component_signature`| Boolean | Verify registrations with `wasmsign2 verify`.                          | No       | `false` |
| `component_cache_base_dir`  | String  | Base directory for per-component collateral cache folders (`<base>/<component_id>`). | No | `.wasm-verification-component-cache/components` |


## Configuration Examples

Running with a built-in RVPS:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "LocalFs"
            "file_path": "/var/lib/attestation-service/reference-values"
        }
    },
    "attestation_token_broker": {
        "duration_min": 5
    }
}
```

Running with a remote RVPS:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5
    }
}
```

Configurations for token signer

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "attestation_token_broker": {
        "duration_min": 5,
        "issuer_name": "some-body",
        "signer": {
            "key_path": "/etc/coco-as/signer.key",
            "cert_url": "https://example.io/coco-as-certchain",
            "cert_path": "/etc/coco-as/signer.pub"
        }
    }
}
```

Register component first:

```json
{
    "component": "<base64(URL_SAFE_NO_PAD) raw wasm component bytes>"
}
```

API response:

```json
{
    "component_id": "component-<sha256>"
}
```

Then use `wasm-verification-component` at request level:

```json
{
    "verification_requests": [{
        "tee": "tdx",
        "verifier": "wasm-verification-component",
        "evidence": "<base64(URL_SAFE_NO_PAD) of the JSON below>"
    }],
    "policy_ids": ["default"]
}
```

Decoded `evidence` JSON example:

```json
{
    "component_id": "component-<sha256>",
    "evidence": {
        "quote": "...",
        "cc_eventlog": "..."
    },
    "pccs_url": "https://your-pccs.example.com",
    "tee_class": "cpu"
}
```

Notes:
1. `verifier` can be `native` (default) or `wasm-verification-component`.
2. `tee` is still required and is used for token metadata/policy context.
3. Attestation request should provide `component_id` (not wasm bytes) when using this backend.
4. Cache location is host-managed. Each registered component gets its own cache directory under `component_cache_base_dir`.
5. `evidence` inside wrapped JSON can contain any verifier-specific schema, so this path is not limited to TDX/SNP.
