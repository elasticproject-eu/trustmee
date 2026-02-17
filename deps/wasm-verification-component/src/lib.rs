use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};

wasmtime::component::bindgen!({
    path: "wit",
    world: "verifier",
});

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub cache_dir: PathBuf,
    pub pccs_url: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from(".wasm-verification-component-cache"),
            pccs_url: None,
        }
    }
}

pub struct WasmVerificationComponent {
    engine: Engine,
}

pub struct LoadedWasmComponent {
    component: Component,
}

impl WasmVerificationComponent {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config).context("create wasmtime engine")?;
        Ok(Self { engine })
    }

    pub fn verify_bytes(
        &self,
        component_bytes: &[u8],
        evidence_bytes: &[u8],
        options: &VerifyOptions,
    ) -> Result<Value> {
        self.verify_bytes_with_expected_data(component_bytes, evidence_bytes, None, None, options)
    }

    pub fn verify_bytes_with_expected_data(
        &self,
        component_bytes: &[u8],
        evidence_bytes: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        std::fs::create_dir_all(&options.cache_dir)
            .with_context(|| format!("create {}", options.cache_dir.display()))?;

        let component = self
            .load_component(component_bytes)
            .context("load wasm verifier component")?;

        self.verify_loaded_component_with_expected_data(
            &component,
            evidence_bytes,
            expected_report_data,
            expected_init_data_hash,
            options,
        )
    }

    pub fn load_component(&self, component_bytes: &[u8]) -> Result<LoadedWasmComponent> {
        let component = Component::from_binary(&self.engine, component_bytes)
            .context("compile wasm verifier component")?;
        Ok(LoadedWasmComponent { component })
    }

    pub fn verify_loaded_component(
        &self,
        component: &LoadedWasmComponent,
        evidence_bytes: &[u8],
        options: &VerifyOptions,
    ) -> Result<Value> {
        self.verify_loaded_component_with_expected_data(
            component,
            evidence_bytes,
            None,
            None,
            options,
        )
    }

    pub fn verify_loaded_component_with_expected_data(
        &self,
        component: &LoadedWasmComponent,
        evidence_bytes: &[u8],
        expected_report_data: Option<&[u8]>,
        expected_init_data_hash: Option<&[u8]>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        std::fs::create_dir_all(&options.cache_dir)
            .with_context(|| format!("create {}", options.cache_dir.display()))?;

        let mut linker = Linker::<HostState>::new(&self.engine);
        wasmtime_wasi::add_to_linker_sync(&mut linker).context("link wasi")?;
        wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker).context("link wasi-http")?;

        let state = HostState::new(&options.cache_dir)?;
        let mut store = Store::new(&self.engine, state);

        let bindings = Verifier::instantiate(&mut store, &component.component, &linker)
            .context("instantiate verifier component")?;
        let verifier_iface = bindings.trustee_verifier_verifier_interface();
        let verifier = verifier_iface.verifier();
        let verifier_resource = verifier
            .call_constructor(&mut store)
            .context("construct verifier resource")?;

        let expected_report_data = match expected_report_data {
            Some(data) => {
                exports::trustee::verifier::verifier_interface::OptionalData::Value(data.to_vec())
            }
            None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
        };
        let expected_init_data_hash = match expected_init_data_hash {
            Some(data) => {
                exports::trustee::verifier::verifier_interface::OptionalData::Value(data.to_vec())
            }
            None => exports::trustee::verifier::verifier_interface::OptionalData::NotProvided,
        };

        let evidence_bytes = add_pccs_url_to_evidence(evidence_bytes, options.pccs_url.as_deref())
            .context("attach optional pccs_url to evidence")?;

        let out = verifier
            .call_evaluate(
                &mut store,
                verifier_resource,
                &evidence_bytes,
                &expected_report_data,
                &expected_init_data_hash,
            )
            .context("run attestation verification")?;

        let value: Value =
            serde_json::from_str(&out).context("component returned non-JSON output")?;
        if let Some(err) = value.get("error") {
            return Err(anyhow!("attestation verification failed: {err}"));
        }

        Ok(value)
    }

    pub fn verify_paths(
        &self,
        component_path: impl AsRef<Path>,
        evidence_path: impl AsRef<Path>,
        options: &VerifyOptions,
    ) -> Result<Value> {
        let component_path = component_path.as_ref();
        let evidence_path = evidence_path.as_ref();

        let component_bytes = std::fs::read(component_path)
            .with_context(|| format!("read {}", component_path.display()))?;
        let evidence_bytes = std::fs::read(evidence_path)
            .with_context(|| format!("read {}", evidence_path.display()))?;

        self.verify_bytes(&component_bytes, &evidence_bytes, options)
    }
}

fn add_pccs_url_to_evidence(evidence_bytes: &[u8], pccs_url: Option<&str>) -> Result<Vec<u8>> {
    let Some(pccs_url) = pccs_url else {
        return Ok(evidence_bytes.to_vec());
    };

    let mut value: Value = serde_json::from_slice(evidence_bytes)
        .context("evidence must be valid JSON when `pccs_url` is provided")?;

    match value {
        Value::Object(ref mut map) => {
            map.insert("pccs_url".to_string(), Value::String(pccs_url.to_string()));
            serde_json::to_vec(&value).context("serialize evidence with pccs_url")
        }
        _ => Err(anyhow!(
            "evidence must be a JSON object when `pccs_url` is provided"
        )),
    }
}

pub fn verify_evidence(component_bytes: &[u8], evidence_bytes: &[u8]) -> Result<Value> {
    let verifier = WasmVerificationComponent::new()?;
    verifier.verify_bytes(component_bytes, evidence_bytes, &VerifyOptions::default())
}

pub fn verify_evidence_with_expected_data(
    component_bytes: &[u8],
    evidence_bytes: &[u8],
    expected_report_data: Option<&[u8]>,
    expected_init_data_hash: Option<&[u8]>,
) -> Result<Value> {
    let verifier = WasmVerificationComponent::new()?;
    verifier.verify_bytes_with_expected_data(
        component_bytes,
        evidence_bytes,
        expected_report_data,
        expected_init_data_hash,
        &VerifyOptions::default(),
    )
}

struct HostState {
    table: ResourceTable,
    wasi: wasmtime_wasi::WasiCtx,
    http: wasmtime_wasi_http::WasiHttpCtx,
}

impl HostState {
    fn new(cache_dir: &Path) -> Result<Self> {
        let mut wasi = wasmtime_wasi::WasiCtxBuilder::new();
        wasi.inherit_stdio();

        use wasmtime_wasi::{DirPerms, FilePerms};
        wasi.preopened_dir(cache_dir, "cache", DirPerms::all(), FilePerms::all())
            .with_context(|| format!("preopen {}", cache_dir.display()))?;

        Ok(Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
        })
    }
}

impl wasmtime_wasi::WasiView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut wasmtime_wasi::WasiCtx {
        &mut self.wasi
    }
}

impl wasmtime_wasi_http::WasiHttpView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut wasmtime_wasi_http::WasiHttpCtx {
        &mut self.http
    }
}
