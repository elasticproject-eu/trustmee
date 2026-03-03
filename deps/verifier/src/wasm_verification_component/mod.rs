use std::{
    collections::HashMap,
    path::PathBuf,
    process::Command,
    sync::{Arc, OnceLock, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wasm_verification_component::{LoadedWasmComponent, VerifyOptions, WasmVerificationComponent};

use crate::{InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};

#[derive(Clone, Debug)]
pub struct ComponentRegistryConfig {
    pub verify_component_signature: bool,
    pub component_cache_base_dir: PathBuf,
}

impl Default for ComponentRegistryConfig {
    fn default() -> Self {
        Self {
            verify_component_signature: false,
            component_cache_base_dir: default_component_cache_base_dir(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct WasmVerificationComponentEvidence {
    /// Registry key for a previously registered component.
    component_id: String,

    /// Tee-specific evidence passed to the verifier component.
    evidence: TeeEvidence,

    /// Optional PCCS URL, used by TDX verifier components.
    #[serde(default)]
    pccs_url: Option<String>,

    /// Optional claim class to return for this verifier.
    #[serde(default = "default_tee_class")]
    tee_class: String,
}

#[derive(Clone)]
struct RegisteredComponent {
    component: Arc<LoadedWasmComponent>,
    cache_dir: PathBuf,
}

struct ComponentRegistry {
    verifier: Arc<WasmVerificationComponent>,
    id_to_component: HashMap<String, RegisteredComponent>,
    hash_to_id: HashMap<[u8; 32], String>,
    config: ComponentRegistryConfig,
}

impl ComponentRegistry {
    fn new(config: ComponentRegistryConfig) -> Result<Self> {
        let verifier = Arc::new(
            WasmVerificationComponent::new().context("initialize wasm-verification-component")?,
        );
        std::fs::create_dir_all(&config.component_cache_base_dir)
            .with_context(|| format!("create {}", config.component_cache_base_dir.display()))?;

        Ok(Self {
            verifier,
            id_to_component: HashMap::new(),
            hash_to_id: HashMap::new(),
            config,
        })
    }

    fn configure(&mut self, config: ComponentRegistryConfig) -> Result<()> {
        std::fs::create_dir_all(&config.component_cache_base_dir)
            .with_context(|| format!("create {}", config.component_cache_base_dir.display()))?;
        self.config = config;
        Ok(())
    }

    fn register_component(&mut self, component_bytes: &[u8]) -> Result<String> {
        if self.config.verify_component_signature {
            verify_component_signature_with_wasmsign2(component_bytes)
                .context("verify component signature with wasmsign2")?;
        }

        let hash = hash_component(component_bytes);
        if let Some(existing) = self.hash_to_id.get(&hash) {
            return Ok(existing.clone());
        }

        let component_id = component_id_from_hash(&hash);
        let cache_dir = self.config.component_cache_base_dir.join(&component_id);
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create {}", cache_dir.display()))?;

        let loaded_component = Arc::new(
            self.verifier
                .load_component(component_bytes)
                .context("load and compile wasm component")?,
        );

        self.id_to_component.insert(
            component_id.clone(),
            RegisteredComponent {
                component: loaded_component,
                cache_dir,
            },
        );
        self.hash_to_id.insert(hash, component_id.clone());

        Ok(component_id)
    }

    fn get_component(&self, component_id: &str) -> Option<RegisteredComponent> {
        self.id_to_component.get(component_id).cloned()
    }
}

fn default_tee_class() -> String {
    "cpu".to_string()
}

fn default_component_cache_base_dir() -> PathBuf {
    PathBuf::from(".wasm-verification-component-cache/components")
}

fn hash_component(component_bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(component_bytes);
    digest.into()
}

fn component_id_from_hash(hash: &[u8; 32]) -> String {
    format!("component-{}", hex::encode(hash))
}

fn verify_component_signature_with_wasmsign2(component_bytes: &[u8]) -> Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = std::env::temp_dir().join(format!(
        "trustee-wasm-component-{}-{timestamp}.wasm",
        std::process::id()
    ));

    std::fs::write(&temp_path, component_bytes)
        .with_context(|| format!("write {}", temp_path.display()))?;

    let output = Command::new("wasmsign2")
        .arg("verify")
        .arg(&temp_path)
        .output()
        .context("run `wasmsign2 verify`")?;

    let _ = std::fs::remove_file(&temp_path);

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "wasmsign2 verification failed (status: {}): stdout=`{stdout}` stderr=`{stderr}`",
            output.status
        );
    }

    Ok(())
}

static COMPONENT_REGISTRY: OnceLock<Result<RwLock<ComponentRegistry>, String>> = OnceLock::new();

fn component_registry() -> Result<&'static RwLock<ComponentRegistry>> {
    let registry = COMPONENT_REGISTRY.get_or_init(|| {
        ComponentRegistry::new(ComponentRegistryConfig::default())
            .map(RwLock::new)
            .map_err(|e| format!("{e:#}"))
    });
    match registry {
        Ok(registry) => Ok(registry),
        Err(err) => bail!("initialize wasm component registry: {err}"),
    }
}

pub fn configure_component_registry(config: ComponentRegistryConfig) -> Result<()> {
    let registry = component_registry()?;
    let mut registry = registry
        .write()
        .map_err(|_| anyhow!("component registry lock poisoned"))?;
    registry.configure(config)
}

pub fn register_component(component_bytes: &[u8]) -> Result<String> {
    let registry = component_registry()?;
    let mut registry = registry
        .write()
        .map_err(|_| anyhow!("component registry lock poisoned"))?;
    registry.register_component(component_bytes)
}

pub struct WasmVerificationComponentDriver;

impl WasmVerificationComponentDriver {
    pub fn new() -> Result<Self> {
        let _ = component_registry()?;
        Ok(Self)
    }
}

#[async_trait]
impl Verifier for WasmVerificationComponentDriver {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let wrapped: WasmVerificationComponentEvidence = serde_json::from_value(evidence).context(
            "for verifier `wasm-verification-component`, evidence must contain \
                 `component_id` and nested `evidence` fields",
        )?;

        let evidence_bytes =
            serde_json::to_vec(&wrapped.evidence).context("serialize nested evidence")?;

        let (verifier, registered_component) = {
            let registry = component_registry()?;
            let registry = registry
                .read()
                .map_err(|_| anyhow!("component registry lock poisoned"))?;
            let registered_component = registry
                .get_component(&wrapped.component_id)
                .ok_or_else(|| {
                    anyhow!(
                        "component_id `{}` is not registered. Register it via component registration API first",
                        wrapped.component_id
                    )
                })?;
            (Arc::clone(&registry.verifier), registered_component)
        };

        let options = VerifyOptions {
            cache_dir: registered_component.cache_dir,
            pccs_url: wrapped.pccs_url,
        };

        let expected_report_data = match expected_report_data {
            ReportData::Value(data) => Some(data.to_vec()),
            ReportData::NotProvided => None,
        };

        let expected_init_data_hash = match expected_init_data_hash {
            InitDataHash::Value(data) => Some(data.to_vec()),
            InitDataHash::NotProvided => None,
        };

        // Run wasm verification on a dedicated OS thread to avoid nested-runtime
        // panics from sync Wasmtime/WASI-HTTP shims inside async server runtimes.
        let component = Arc::clone(&registered_component.component);
        let claims = std::thread::spawn(move || {
            verifier.verify_loaded_component_with_expected_data(
                component.as_ref(),
                &evidence_bytes,
                expected_report_data.as_deref(),
                expected_init_data_hash.as_deref(),
                &options,
            )
        })
        .join()
        .map_err(|_| anyhow!("wasm-verification-component evaluate thread panicked"))?
        .map_err(|e| anyhow!("wasm-verification-component evaluate failed: {e:#}"))?;

        Ok(vec![(claims, wrapped.tee_class)])
    }
}

#[cfg(test)]
mod tests {
    use super::{
        component_id_from_hash, default_component_cache_base_dir, default_tee_class,
        ComponentRegistryConfig, WasmVerificationComponentEvidence,
    };

    #[test]
    fn test_default_tee_class() {
        assert_eq!(default_tee_class(), "cpu");
    }

    #[test]
    fn test_default_component_cache_base_dir() {
        assert_eq!(
            default_component_cache_base_dir().to_string_lossy(),
            ".wasm-verification-component-cache/components"
        );
    }

    #[test]
    fn test_registry_config_defaults_signature_check_disabled() {
        let cfg = ComponentRegistryConfig::default();
        assert!(!cfg.verify_component_signature);
    }

    #[test]
    fn test_deserialize_wrapped_evidence() {
        let raw = r#"
        {
            "component_id": "component-abc",
            "evidence": { "quote": "Zm9v" },
            "pccs_url": "https://pccs.example"
        }
        "#;

        let wrapped: WasmVerificationComponentEvidence =
            serde_json::from_str(raw).expect("deserialize wrapped evidence");
        assert_eq!(wrapped.tee_class, "cpu");
        assert_eq!(wrapped.component_id, "component-abc");
        assert_eq!(wrapped.pccs_url.as_deref(), Some("https://pccs.example"));
    }

    #[test]
    fn test_component_id_from_hash_is_deterministic() {
        let hash = [0xAB; 32];
        let id = component_id_from_hash(&hash);
        assert!(id.starts_with("component-"));
        assert!(id.ends_with(&"ab".repeat(32)));
    }
}
