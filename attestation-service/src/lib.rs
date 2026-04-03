//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.

pub mod config;
pub mod ear_token;
pub mod policy_engine;
pub mod rvps;
use crate::rvps::RvpsClient;

use canon_json::CanonicalFormatter;
pub use kbs_types::{Attestation, HashAlgorithm, Tee};
pub use serde_json::Value;

use anyhow::{anyhow, bail, Context, Result};
use config::Config;
use rvps::RvpsError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio::fs;
use tracing::{debug, info};
use verifier::{InitDataHash, ReportData, TeeEvidenceParsedClaim};

use crate::ear_token::EarAttestationTokenBroker;

fn serialize_canon_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut ser)?;
    Ok(buf)
}

pub type TeeEvidence = serde_json::Value;
pub type TeeClass = String;

#[derive(Clone, Copy, Debug, Default)]
pub enum VerifierType {
    #[default]
    Native,
    WasmVerificationComponent,
}

/// Tee Claims are the output of the verifier plus some metadata
/// that identifies the TEE type and class.
#[derive(Debug, Serialize)]
pub struct TeeClaims {
    tee: Tee,
    tee_class: TeeClass,
    claims: TeeEvidenceParsedClaim,
    init_data_claims: serde_json::Value,
    runtime_data_claims: serde_json::Value,
}

/// Runtime Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug)]
pub enum RuntimeData {
    /// This will be used as the expected runtime data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime data in a JSON map. CoCoAS will rearrange each layer of the
    /// data JSON object in dictionary order by key, then serialize and output
    /// it into a compact string, and perform hash calculation on the whole
    /// to check against the one inside evidence.
    Structured(Value),
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Create AS work dir failed: {0}")]
    CreateDir(#[source] std::io::Error),
    #[error("Policy Engine is not supported: {0}")]
    UnsupportedPolicy(#[source] strum::ParseError),
    #[error("Create rvps failed: {0}")]
    Rvps(#[source] RvpsError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Initdata defined in
/// <https://github.com/confidential-containers/trustee/blob/47d7a2338e0be76308ac19be5c0c172c592780aa/kbs/docs/initdata.md>
#[derive(Debug, Deserialize, Serialize)]
pub struct Initdata {
    pub version: String,
    pub algorithm: HashAlgorithm,
    pub data: HashMap<String, String>,
}

/// Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug)]
pub enum InitDataInput {
    /// This will be used as the expected init data to check against
    /// the one inside evidence.
    Digest(Vec<u8>),

    /// Init data TOML. CoCoAS will perform hash calculation on the whole
    /// to check against the one inside evidence.
    ///
    /// After the verification, the `.data` field of init data field will
    /// be included inside the token claims.
    Toml(String),
}

/// A VerificationRequest contains hw evidence that the AS will verify along with some
/// metadata required for verification.
///
pub struct VerificationRequest {
    /// TEE evidence bytes. This might not be the raw hardware evidence bytes. Definitions
    /// are in `verifier` crate.
    pub evidence: TeeEvidence,
    /// concrete TEE type
    pub tee: Tee,
    /// These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    pub runtime_data: Option<RuntimeData>,
    /// The hash algorithm that is used to calculate the digest of `runtime_data`.
    pub runtime_data_hash_algorithm: HashAlgorithm,
    /// These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    pub init_data: Option<InitDataInput>,
    /// Verifier implementation to use for this request.
    pub verifier: VerifierType,
}

pub struct AttestationService {
    config: Config,
    rvps: RvpsClient,
    token_broker: EarAttestationTokenBroker,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub async fn new(config: Config) -> Result<Self, ServiceError> {
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .await
                .map_err(ServiceError::CreateDir)?;
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "wasm-verification-component-driver")] {
                verifier::wasm_verification_component_driver::configure_component_registry(
                    verifier::wasm_verification_component_driver::ComponentRegistryConfig {
                        verify_component_signature: config
                            .wasm_component_registry
                            .verify_component_signature,
                        component_cache_base_dir: config
                            .wasm_component_registry
                            .component_cache_base_dir
                            .clone(),
                    },
                )
                .context("configure wasm component registry")?;
            }
        }

        let rvps = rvps::initialize_rvps_client(&config.rvps_config)
            .await
            .map_err(ServiceError::Rvps)?;

        let token_broker =
            EarAttestationTokenBroker::new(config.attestation_token_broker.clone()).await?;

        Ok(Self {
            config,
            rvps,
            token_broker,
        })
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.token_broker.set_policy(policy_id, policy).await?;
        Ok(())
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.token_broker
            .list_policies()
            .await
            .context("Cannot List Policy")
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.token_broker
            .get_policy(policy_id)
            .await
            .context("Cannot Get Policy")
    }

    /// Evaluate Attestation Evidence.
    /// Issue an attestation results token which contain TCB status and TEE public key.
    /// An evaluation can cover one more pieces of TEE Evidence which represent the TCB.
    /// The results will be combined into one attestation token.
    /// For more information, see the definition of VerificationRequest above.
    pub async fn evaluate(
        &self,
        verification_requests: Vec<VerificationRequest>,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        let mut tee_claims: Vec<TeeClaims> = vec![];

        if verification_requests.is_empty() {
            bail!("No verification requests provided.")
        }

        for verification_request in verification_requests {
            let verifier = verifier::to_verifier(
                &verification_request.tee,
                self.config.clone().verifier_config,
                matches!(
                    verification_request.verifier,
                    VerifierType::WasmVerificationComponent
                ),
            )
            .await?;

            let (report_data, runtime_data_claims) = parse_runtime_data(
                verification_request.runtime_data,
                &verification_request.runtime_data_hash_algorithm,
            )
            .context("parse runtime data")?;

            let report_data = match &report_data {
                Some(data) => ReportData::Value(data),
                None => ReportData::NotProvided,
            };

            let (init_data, init_data_claims) =
                parse_init_data(verification_request.init_data).context("parse init data")?;

            let init_data_hash = match &init_data {
                Some(data) => InitDataHash::Value(data),
                None => InitDataHash::NotProvided,
            };

            let claims = verifier
                .evaluate(verification_request.evidence, &report_data, &init_data_hash)
                .await
                .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;

            for (claims_from_tee_evidence, tee_class) in claims {
                let claims_from_tee_evidence = match verification_request.verifier {
                    VerifierType::Native => claims_from_tee_evidence,
                    VerifierType::WasmVerificationComponent => {
                        normalize_wasm_verification_component_claims(
                            verification_request.tee,
                            claims_from_tee_evidence,
                        )
                        .context("normalize wasm-verification-component claims")?
                    }
                };

                info!(
                    tee =? verification_request.tee,
                    tee_class = tee_class,
                    "Verifier/endorsement check passed.",
                );

                debug!(
                    "claims = {}, initdata claims = {}, runtime claims = {}",
                    serde_json::to_string(&claims_from_tee_evidence)?,
                    serde_json::to_string(&init_data_claims)?,
                    serde_json::to_string(&runtime_data_claims)?,
                );
                tee_claims.push(TeeClaims {
                    tee: verification_request.tee,
                    tee_class,
                    claims: claims_from_tee_evidence,
                    init_data_claims: init_data_claims.clone(),
                    runtime_data_claims: runtime_data_claims.clone(),
                });
            }
        }

        let attestation_results_token = self
            .token_broker
            .issue(tee_claims, policy_ids, Some(self.rvps.clone()))
            .await?;
        Ok(attestation_results_token)
    }

    /// Register a new reference value
    pub async fn register_reference_value(&mut self, message: &str) -> Result<()> {
        self.rvps
            .lock()
            .await
            .verify_and_extract(message)
            .await
            .context("register reference value")
    }

    /// Query Reference Values
    pub async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        self.rvps
            .lock()
            .await
            .query_reference_value(reference_value_id)
            .await
            .context("query reference values")
    }

    pub async fn generate_supplemental_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> Result<String> {
        let verifier =
            verifier::to_verifier(&tee, self.config.clone().verifier_config, false).await?;
        verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
    }
}

/// Get the expected runtime data and potential claims due to the given input
/// and the hash algorithm
fn parse_runtime_data(
    data: Option<RuntimeData>,
    hash_algorithm: &HashAlgorithm,
) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            RuntimeData::Raw(raw) => Ok((Some(raw), Value::Null)),
            RuntimeData::Structured(structured) => {
                // by default serde_json will enforence the alphabet order for keys
                let hash_materials =
                    serialize_canon_json(&structured).context("parse JSON structured data")?;
                let digest = hash_algorithm.digest(&hash_materials);
                Ok((Some(digest), structured))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

/// Get the expected init data and potential claims due to the given input
/// and the hash algorithm
fn parse_init_data(data: Option<InitDataInput>) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            InitDataInput::Digest(raw) => Ok((Some(raw), Value::Null)),
            InitDataInput::Toml(structured) => {
                let initdata = toml::from_str::<Initdata>(&structured)
                    .context("parse TOML structured data")?;
                let digest = initdata.algorithm.digest(&structured.into_bytes());

                let mut claims = serde_json::to_value(initdata.data)?;

                // Transform certain claims from toml to json if they exist and are toml.
                if let Value::Object(ref mut map) = claims {
                    for key in ["cdh.toml", "aa.toml"] {
                        if let Some(Value::String(toml_str)) = map.get(key).cloned() {
                            if let Ok(toml_value) = toml::from_str::<toml::Value>(&toml_str) {
                                if let Ok(json_value) = serde_json::to_value(toml_value) {
                                    map.insert(key.to_string(), json_value);
                                }
                            }
                        }
                    }

                    // If there is a policy rego file, replace the full policy file
                    // with some claims extracted from the file.
                    if let Some(Value::String(rego_str)) = map.get("policy.rego").cloned() {
                        if let Some(policy_data) = extract_policy_data(&rego_str) {
                            // Since we found some policy claims, remove the original
                            // policy rego from the claims.
                            map.remove("policy.rego");
                            map.insert("agent_policy_claims".to_string(), policy_data);
                        }
                    }
                }
                Ok((Some(digest), claims))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

fn normalize_wasm_verification_component_claims(
    tee: Tee,
    claims: TeeEvidenceParsedClaim,
) -> Result<TeeEvidenceParsedClaim> {
    let mut claims_map = claims
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("wasm-verification-component claims must be a JSON object"))?;

    let report_data = claims_map.remove("report_data");
    let init_data = claims_map.remove("init_data");
    let claims_type = remove_required_string_claim(&mut claims_map, "claims_type")?;
    let expected_claims_type = tee_name(tee);

    if claims_type != expected_claims_type {
        bail!(
            "wasm-verification-component claims_type `{claims_type}` does not match request tee `{expected_claims_type}`"
        );
    }

    let verifier_component_sha256 =
        remove_required_string_claim(&mut claims_map, "verifier_component_sha256")?;
    let nested_claims = claims_map
        .remove("claims")
        .ok_or_else(|| anyhow!("wasm-verification-component claims must include `claims`"))?;
    let mut normalized_claims = nested_claims.as_object().cloned().ok_or_else(|| {
        anyhow!("wasm-verification-component claim `claims` must be a JSON object")
    })?;

    let mut wasm_metadata = serde_json::Map::new();
    wasm_metadata.insert("claims_type".to_string(), Value::String(claims_type));
    wasm_metadata.insert(
        "verifier_component_sha256".to_string(),
        Value::String(verifier_component_sha256),
    );
    for (key, value) in claims_map {
        wasm_metadata.insert(key, value);
    }

    normalized_claims.insert(
        "wasm_verification_component".to_string(),
        Value::Object(wasm_metadata),
    );

    if let Some(report_data) = report_data {
        normalized_claims.insert("report_data".to_string(), report_data);
    }
    if let Some(init_data) = init_data {
        normalized_claims.insert("init_data".to_string(), init_data);
    }

    Ok(Value::Object(normalized_claims))
}

fn remove_required_string_claim(
    claims_map: &mut serde_json::Map<String, Value>,
    claim_name: &str,
) -> Result<String> {
    match claims_map.remove(claim_name) {
        Some(Value::String(value)) => Ok(value),
        Some(_) => bail!("wasm-verification-component claim `{claim_name}` must be a string"),
        None => bail!("wasm-verification-component claims must include `{claim_name}`"),
    }
}

fn tee_name(tee: Tee) -> &'static str {
    match tee {
        Tee::AzSnpVtpm => "az-snp-vtpm",
        Tee::AzTdxVtpm => "az-tdx-vtpm",
        Tee::Nvidia => "nvidia",
        Tee::Sev => "sev",
        Tee::Sgx => "sgx",
        Tee::Snp => "snp",
        Tee::Tdx => "tdx",
        Tee::Cca => "cca",
        Tee::Csv => "csv",
        Tee::Se => "se",
        Tee::HygonDcu => "hygondcu",
        Tee::Tpm => "tpm",
        Tee::Sample => "sample",
        Tee::SampleDevice => "sampledevice",
    }
}

/// Extract the 'policy_data' JSON from a rego policy file.
/// Ideally the runtime will separate the policy and the
/// policy data. Until then, do this workaround.
///
/// Assume that the policy_data is the last thing in the rego file.
fn extract_policy_data(rego_content: &str) -> Option<Value> {
    // Find where policy_data is declared.
    let start_pattern = "policy_data := {";
    let start_idx = rego_content.find(start_pattern)?;

    let json_start = start_idx + start_pattern.len() - 1;
    let json_str = &rego_content[json_start..];

    serde_json::from_str(json_str).ok()
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    #[cfg(feature = "wasm-verification-component-driver")]
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};

    use crate::{normalize_wasm_verification_component_claims, HashAlgorithm, RuntimeData};

    #[cfg(feature = "wasm-verification-component-driver")]
    use {
        base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
        ciborium::into_writer,
        reference_value_provider_service::storage::{local_fs, ReferenceValueStorageConfig},
        sev::{
            firmware::{guest::AttestationReport, host::CertTableEntry},
            parser::ByteParser,
        },
        sha2::Digest,
        std::{collections::BTreeMap, fs, path::PathBuf},
        tempfile::TempDir,
        wasm_verification_component::{
            component_id_for_component_bytes, SNP_COLLATERAL_MEDIA_TYPE, TRUSTMEE_COLLECTION_TYPE,
            TRUSTMEE_EAT_PROFILE,
        },
    };

    #[cfg(feature = "wasm-verification-component-driver")]
    const CMW_INDICATOR_ENDORSEMENT: u64 = 1 << 1;
    #[cfg(feature = "wasm-verification-component-driver")]
    const CMW_INDICATOR_EVIDENCE: u64 = 1 << 2;

    #[cfg(feature = "wasm-verification-component-driver")]
    #[derive(Debug, Deserialize)]
    struct SnpEvidence {
        attestation_report: AttestationReport,
        cert_chain: Option<Vec<CertTableEntry>>,
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    #[derive(Debug, Serialize)]
    struct SnpCollateral {
        cert_chain: Vec<CertTableEntry>,
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    #[derive(Debug, Serialize)]
    struct CborEatClaims {
        eat_profile: String,
        component_id: String,
        evidence: Vec<u8>,
        evidence_type: String,
    }

    #[rstest]
    #[case(Some(RuntimeData::Raw(b"aaaaa".to_vec())), Some(b"aaaaa".to_vec()), HashAlgorithm::Sha384, Value::Null)]
    #[case(None, None, HashAlgorithm::Sha384, Value::Null)]
    #[case(Some(RuntimeData::Structured(json!({"b": 1, "a": "test", "c": {"d": "e"}}))), Some(hex::decode(b"e71ce8e70d814ba6639c3612ebee0ff1f76f650f8dbb5e47157e0f3f525cd22c4597480a186427c813ca941da78870c3").unwrap()), HashAlgorithm::Sha384, json!({"b": 1, "a": "test", "c": {"d": "e"}}))]
    fn parse_runtimedata_json_binding(
        #[case] input: Option<RuntimeData>,
        #[case] expected_data: Option<Vec<u8>>,
        #[case] hash_algorithm: HashAlgorithm,
        #[case] expected_claims: Value,
    ) {
        let (data, data_claims) =
            crate::parse_runtime_data(input, &hash_algorithm).expect("parse failed");
        assert_eq!(data, expected_data);
        assert_json_eq!(data_claims, expected_claims);
    }

    #[test]
    fn normalize_wasm_claims_promotes_nested_claims_and_keeps_metadata() {
        let normalized = normalize_wasm_verification_component_claims(
            crate::Tee::Snp,
            json!({
                "claims_type": "snp",
                "claims": {
                    "measurement": "012345",
                    "reported_tcb_snp": 23
                },
                "report_data": "abcdef",
                "init_data": "fedcba",
                "verifier_component_sha256": "deadbeef"
            }),
        )
        .expect("normalize wasm claims");

        assert_json_eq!(
            normalized,
            json!({
                "measurement": "012345",
                "reported_tcb_snp": 23,
                "report_data": "abcdef",
                "init_data": "fedcba",
                "wasm_verification_component": {
                    "claims_type": "snp",
                    "verifier_component_sha256": "deadbeef"
                }
            })
        );
    }

    #[test]
    fn normalize_wasm_claims_rejects_mismatched_requested_tee() {
        let err = normalize_wasm_verification_component_claims(
            crate::Tee::Tdx,
            json!({
                "claims_type": "snp",
                "claims": {
                    "measurement": "012345"
                },
                "verifier_component_sha256": "deadbeef"
            }),
        )
        .expect_err("mismatched tee should fail");

        assert!(
            format!("{err:#}").contains("does not match request tee"),
            "unexpected error: {err:#}"
        );
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn trustmee_library_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("platform-agnostic-attestation-verification root")
            .parent()
            .expect("trustmee2 root")
            .join("trustmee-verification-library")
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn snp_component_bytes() -> Vec<u8> {
        fs::read(
            trustmee_library_root()
                .join("test_data")
                .join("snp_verifier_host_crypto_component.wasm"),
        )
        .expect("read SNP verifier component bytes")
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn snp_report_and_collateral() -> (Vec<u8>, Vec<u8>) {
        let bytes = fs::read(
            trustmee_library_root()
                .join("test_data")
                .join("snp_evidence.json"),
        )
        .expect("read SNP evidence");
        let parsed: SnpEvidence = serde_json::from_slice(&bytes).expect("parse SNP evidence");
        let cert_chain = parsed
            .cert_chain
            .clone()
            .expect("sample SNP evidence includes cert_chain");
        let report_bytes = parsed
            .attestation_report
            .to_bytes()
            .expect("encode attestation report")
            .to_vec();

        let collateral = SnpCollateral { cert_chain };
        let mut collateral_bytes = Vec::new();
        into_writer(&collateral, &mut collateral_bytes).expect("encode SNP collateral");

        (report_bytes, collateral_bytes)
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn build_json_cmw(
        component_id: &str,
        evidence_bytes: &[u8],
        evidence_type: &str,
        entries: Vec<(&str, &str, Vec<u8>, u64)>,
    ) -> Vec<u8> {
        let eat = json!({
            "eat_profile": TRUSTMEE_EAT_PROFILE,
            "component_id": component_id,
            "evidence_type": evidence_type,
            "evidence": URL_SAFE_NO_PAD.encode(evidence_bytes),
        });
        let eat_payload = serde_json::to_vec(&eat).expect("serialize JSON EAT");

        let mut collection = serde_json::Map::new();
        collection.insert(
            "__cmwc_t".to_string(),
            Value::String(TRUSTMEE_COLLECTION_TYPE.to_string()),
        );
        collection.insert(
            "evidence".to_string(),
            json!([
                format!(
                    "application/eat-ucs+json; eat_profile=\"{}\"",
                    TRUSTMEE_EAT_PROFILE
                ),
                URL_SAFE_NO_PAD.encode(eat_payload),
                CMW_INDICATOR_EVIDENCE
            ]),
        );

        for (label, media_type, payload, indicator) in entries {
            collection.insert(
                label.to_string(),
                json!([media_type, URL_SAFE_NO_PAD.encode(payload), indicator]),
            );
        }

        serde_json::to_vec(&collection).expect("serialize JSON CMW")
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn build_cbor_cmw(
        component_id: &str,
        evidence_bytes: &[u8],
        evidence_type: &str,
        entries: Vec<(&str, &str, Vec<u8>, u64)>,
    ) -> Vec<u8> {
        let eat = CborEatClaims {
            eat_profile: TRUSTMEE_EAT_PROFILE.to_string(),
            component_id: component_id.to_string(),
            evidence: evidence_bytes.to_vec(),
            evidence_type: evidence_type.to_string(),
        };
        let mut eat_payload = Vec::new();
        into_writer(&eat, &mut eat_payload).expect("encode CBOR EAT");

        let mut collection: BTreeMap<String, Value> = BTreeMap::new();
        collection.insert(
            "__cmwc_t".to_string(),
            Value::String(TRUSTMEE_COLLECTION_TYPE.to_string()),
        );
        collection.insert(
            "evidence".to_string(),
            json!([
                format!(
                    "application/eat-ucs+cbor; eat_profile=\"{}\"",
                    TRUSTMEE_EAT_PROFILE
                ),
                URL_SAFE_NO_PAD.encode(eat_payload),
                CMW_INDICATOR_EVIDENCE
            ]),
        );

        for (label, media_type, payload, indicator) in entries {
            collection.insert(
                label.to_string(),
                json!([media_type, URL_SAFE_NO_PAD.encode(payload), indicator]),
            );
        }

        let as_json = serde_json::to_vec(&collection).expect("serialize CBOR helper JSON");
        let parsed_json: Value = serde_json::from_slice(&as_json).expect("parse CBOR helper JSON");
        let cbor_value = json_to_cbor_value(&parsed_json);
        let mut cbor_bytes = Vec::new();
        into_writer(&cbor_value, &mut cbor_bytes).expect("serialize CBOR CMW");
        cbor_bytes
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn json_to_cbor_value(value: &Value) -> ciborium::value::Value {
        match value {
            Value::Null => ciborium::value::Value::Null,
            Value::Bool(value) => ciborium::value::Value::Bool(*value),
            Value::Number(value) => {
                if let Some(value) = value.as_u64() {
                    ciborium::value::Value::Integer(value.into())
                } else if let Some(value) = value.as_i64() {
                    ciborium::value::Value::Integer(value.into())
                } else {
                    ciborium::value::Value::Float(value.as_f64().expect("float"))
                }
            }
            Value::String(value) => {
                if let Ok(bytes) = URL_SAFE_NO_PAD.decode(value) {
                    ciborium::value::Value::Bytes(bytes)
                } else {
                    ciborium::value::Value::Text(value.clone())
                }
            }
            Value::Array(values) => {
                ciborium::value::Value::Array(values.iter().map(json_to_cbor_value).collect())
            }
            Value::Object(values) => ciborium::value::Value::Map(
                values
                    .iter()
                    .map(|(key, value)| {
                        (
                            ciborium::value::Value::Text(key.clone()),
                            json_to_cbor_value(value),
                        )
                    })
                    .collect(),
            ),
        }
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn trustmee_test_config() -> (TempDir, crate::config::Config) {
        let tempdir = TempDir::new().expect("create tempdir");
        let rvps_dir = tempdir.path().join("rvps");
        let cache_dir = tempdir.path().join("component-cache");
        let work_dir = tempdir.path().join("work");
        let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("coco-as")
            .join("policy");

        (
            tempdir,
            crate::config::Config {
                work_dir,
                rvps_config: crate::rvps::RvpsConfig::BuiltIn(crate::rvps::RvpsCrateConfig {
                    storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config {
                        file_path: rvps_dir.display().to_string(),
                    }),
                    extractors: None,
                }),
                attestation_token_broker: crate::ear_token::EarTokenConfiguration {
                    policy_dir: policy_dir.display().to_string(),
                    ..Default::default()
                },
                verifier_config: None,
                wasm_component_registry: crate::config::WasmComponentRegistryConfig {
                    verify_component_signature: false,
                    component_cache_base_dir: cache_dir,
                },
            },
        )
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn decode_jwt_payload(token: &str) -> Value {
        let payload = token
            .split('.')
            .nth(1)
            .expect("JWT payload segment must exist");
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64 decode JWT payload");
        serde_json::from_slice(&payload).expect("parse JWT payload JSON")
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn tdx_component_bytes() -> Vec<u8> {
        fs::read(
            trustmee_library_root()
                .join("test_data")
                .join("tdx_verifier_component.wasm"),
        )
        .expect("read TDX verifier component bytes")
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn tdx_quote_bytes() -> Vec<u8> {
        fs::read(
            trustmee_library_root()
                .join("test_data")
                .join("tdx_quote.bin"),
        )
        .expect("read TDX quote")
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    fn assert_snp_wasm_payload(payload: &Value, expected_hash: &str) {
        let annotated_evidence = &payload["submods"]["cpu0"]["ear.veraison.annotated-evidence"];
        let snp = &annotated_evidence["snp"];
        let snp_claims = snp
            .as_object()
            .expect("snp annotated evidence must be an object");

        assert_eq!(
            snp["wasm_verification_component"]["claims_type"].as_str(),
            Some("snp")
        );
        assert_eq!(
            snp["wasm_verification_component"]["verifier_component_sha256"].as_str(),
            Some(expected_hash)
        );
        assert_eq!(snp["reported_tcb_snp"], 23);
        assert!(
            snp["measurement"]
                .as_str()
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            "measurement claim must be present"
        );
        assert!(
            annotated_evidence["report_data"]
                .as_str()
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            "report_data should stay at the top level"
        );
        assert!(
            annotated_evidence["init_data"]
                .as_str()
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            "init_data should stay at the top level"
        );
        assert!(
            snp_claims.contains_key("wasm_verification_component"),
            "wasm metadata must be preserved under the real tee"
        );
        assert!(snp.get("claims").is_none());
        assert!(snp["wasm_verification_component"]
            .get("report_data")
            .is_none());
        assert!(snp["wasm_verification_component"]
            .get("init_data")
            .is_none());
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    async fn evaluate_wasm_cmw(cmw: Vec<u8>, tee: crate::Tee) -> String {
        let (_tempdir, config) = trustmee_test_config();
        let service = crate::AttestationService::new(config)
            .await
            .expect("create attestation service");

        service
            .evaluate(
                vec![crate::VerificationRequest {
                    evidence: Value::String(URL_SAFE_NO_PAD.encode(cmw)),
                    tee,
                    runtime_data: None,
                    runtime_data_hash_algorithm: crate::HashAlgorithm::Sha384,
                    init_data: None,
                    verifier: crate::VerifierType::WasmVerificationComponent,
                }],
                vec!["default".into()],
            )
            .await
            .expect("evaluate wasm CMW")
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    #[tokio::test]
    async fn wasm_json_snp_cmw_evaluation_returns_snp_token() {
        let component_bytes = snp_component_bytes();
        let expected_hash = hex::encode(sha2::Sha256::digest(&component_bytes));
        let component_id = component_id_for_component_bytes(&component_bytes);
        let (report_bytes, collateral_bytes) = snp_report_and_collateral();
        let cmw = build_json_cmw(
            &component_id,
            &report_bytes,
            "application/octet-stream",
            vec![
                (
                    "verifier",
                    "application/wasm",
                    component_bytes,
                    CMW_INDICATOR_ENDORSEMENT,
                ),
                (
                    "snp-collateral",
                    SNP_COLLATERAL_MEDIA_TYPE,
                    collateral_bytes,
                    CMW_INDICATOR_ENDORSEMENT,
                ),
            ],
        );

        let token = evaluate_wasm_cmw(cmw, crate::Tee::Snp).await;
        let payload = decode_jwt_payload(&token);

        assert!(
            payload.to_string().contains("\"snp\""),
            "decoded token payload should contain snp claims: {payload}"
        );
        assert_snp_wasm_payload(&payload, &expected_hash);
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    #[tokio::test]
    async fn wasm_cbor_snp_cmw_evaluation_returns_snp_token() {
        let component_bytes = snp_component_bytes();
        let expected_hash = hex::encode(sha2::Sha256::digest(&component_bytes));
        let component_id = component_id_for_component_bytes(&component_bytes);
        let (report_bytes, collateral_bytes) = snp_report_and_collateral();
        let cmw = build_cbor_cmw(
            &component_id,
            &report_bytes,
            "application/octet-stream",
            vec![
                (
                    "verifier",
                    "application/wasm",
                    component_bytes,
                    CMW_INDICATOR_ENDORSEMENT,
                ),
                (
                    "snp-collateral",
                    SNP_COLLATERAL_MEDIA_TYPE,
                    collateral_bytes,
                    CMW_INDICATOR_ENDORSEMENT,
                ),
            ],
        );

        let token = evaluate_wasm_cmw(cmw, crate::Tee::Snp).await;
        let payload = decode_jwt_payload(&token);

        assert!(
            payload.to_string().contains("\"snp\""),
            "decoded token payload should contain snp claims: {payload}"
        );
        assert_snp_wasm_payload(&payload, &expected_hash);
    }

    #[cfg(feature = "wasm-verification-component-driver")]
    #[tokio::test]
    #[ignore = "requires Intel collateral connectivity or a pre-populated cache"]
    async fn wasm_json_tdx_cmw_evaluation_returns_tdx_claims_type() {
        let component_bytes = tdx_component_bytes();
        let expected_hash = hex::encode(sha2::Sha256::digest(&component_bytes));
        let component_id = component_id_for_component_bytes(&component_bytes);
        let quote_bytes = tdx_quote_bytes();

        let cmw = build_json_cmw(
            &component_id,
            &quote_bytes,
            "application/octet-stream",
            vec![(
                "verifier",
                "application/wasm",
                component_bytes,
                CMW_INDICATOR_ENDORSEMENT,
            )],
        );

        let token = evaluate_wasm_cmw(cmw, crate::Tee::Tdx).await;
        let payload = decode_jwt_payload(&token);
        let tdx = &payload["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"];

        assert_eq!(
            tdx["wasm_verification_component"]["claims_type"].as_str(),
            Some("tdx")
        );
        assert_eq!(
            tdx["wasm_verification_component"]["verifier_component_sha256"].as_str(),
            Some(expected_hash.as_str())
        );
        assert!(tdx.get("quote").is_some());
    }
}
