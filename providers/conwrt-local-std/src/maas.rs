//! HTTP [`MaasClient`] over `reqwest` — the production MAAS path for the
//! [`conwrt_maas::provider::MaasProvider`] (issue #169, milestones M5).
//!
//! Contract mirrors the region API 2.0 shapes the provider needs:
//!
//! | Provider op        | Region call                             |
//! |--------------------|-----------------------------------------|
//! | `compose`          | `POST /vm-hosts/{id}/op-compose`        |
//! | `machines`         | `GET /machines/`                        |
//! | `machine`          | `GET /machines/{system_id}/`            |
//! | `allocate`         | `POST /machines/?op=allocate`           |
//! | `deploy`           | `POST /machines/{system_id}/?op=deploy` |
//! | `release`          | `POST /machines/{system_id}/?op=release`|
//! | `delete`           | `DELETE /machines/{system_id}/`         |
//!
//! Tests run against `httpmock` (the `conwrt-image` pattern — no real
//! network calls), pinning the documented region API 2.0 shapes. The
//! live-region validation round remains owner-gated (bench hardware).

use std::sync::atomic::{AtomicU64, Ordering};

use conwrt_maas::provider::{MaasClient, MachineRecord, MachineState, VmSpec};
use serde::Deserialize;
use thiserror::Error;

/// Per-call HTTP timeout (the region API answers <1s on the lab Pi).
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Failures of the HTTP MAAS client.
#[derive(Debug, Error)]
pub enum MaasHttpError {
    /// Transport-level failure (connect, DNS, timeout).
    #[error("MAAS HTTP call failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The region answered with a non-2xx status.
    #[error("MAAS API error {status}: {body}")]
    Api {
        /// HTTP status the region returned.
        status: reqwest::StatusCode,
        /// Truncated response body.
        body: String,
    },
    /// The response could not be parsed as the expected machine shape.
    #[error("MAAS response parse error: {0}")]
    Parse(String),
    /// The base URL was malformed.
    #[error("invalid MAAS base URL {0}")]
    Url(String),
    /// OAuth credentials over a plaintext (http) transport — RFC 5849
    /// §3.4.4 requires TLS for PLAINTEXT credentials.
    #[error(
        "refusing to send API credentials over non-HTTPS transport {0} (set allow_insecure_http for isolated lab regions)"
    )]
    InsecureTransport(String),
    /// `op-allocate` by name returned a different machine than the
    /// composed one — the allocation is NOT what the caller asked for.
    #[error("allocate returned {allocated} but the composed machine is {requested}")]
    AllocateMismatch {
        /// The machine the provider composed and meant to allocate.
        requested: String,
        /// The machine MAAS actually allocated (now leaked unless released).
        allocated: String,
    },
}

/// MAAS API key (the `consumer_key:token:secret` triple the region
/// issues; in token mode the consumer secret is empty).
#[derive(Debug, Clone)]
pub struct MaasCredentials {
    /// OAuth1 consumer key.
    pub consumer_key: String,
    /// OAuth1 token.
    pub token: String,
    /// Token secret (signs PLAINTEXT requests as `&{secret}`).
    pub secret: String,
}

impl MaasCredentials {
    /// Parse a `consumer_key:token:secret` triple.
    pub fn parse(api_key: &str) -> Result<Self, MaasHttpError> {
        let parts: Vec<&str> = api_key.split(':').collect();
        match parts[..] {
            [ck, token, secret] if !ck.is_empty() && !token.is_empty() && !secret.is_empty() => {
                Ok(Self {
                    consumer_key: ck.to_string(),
                    token: token.to_string(),
                    secret: secret.to_string(),
                })
            }
            _ => Err(MaasHttpError::Parse(format!(
                "MAAS API key must be consumer_key:token:secret, got {api_key:?}"
            ))),
        }
    }
}

/// reqwest-backed [`MaasClient`]. Clone-safe (pooled HTTP client).
#[derive(Debug, Clone)]
pub struct HttpMaasClient {
    base: reqwest::Url,
    credentials: Option<MaasCredentials>,
    insecure_http: bool,
    vm_host_id: String,
    http: reqwest::Client,
}

/// Wire shape of a machine record (the fields the provider consumes).
#[derive(Debug, Deserialize)]
struct MachineJson {
    system_id: String,
    hostname: String,
    status_name: String,
}

impl MachineJson {
    fn into_record(self) -> Result<MachineRecord, MaasHttpError> {
        let state = self.status_name.parse::<MachineState>().map_err(|()| {
            MaasHttpError::Parse(format!("bad status_name {:#?}", self.status_name))
        })?;
        Ok(MachineRecord {
            system_id: self.system_id,
            hostname: self.hostname,
            state,
        })
    }
}

impl HttpMaasClient {
    /// Client for a region API base (e.g. `http://maas-host:5240/MAAS/api/2.0`)
    /// composing VMs on `vm_host_id`.
    pub fn new(base_url: &str, vm_host_id: &str) -> Result<Self, MaasHttpError> {
        let mut base =
            reqwest::Url::parse(base_url).map_err(|e| MaasHttpError::Url(e.to_string()))?;
        // Endpoint joins below are relative; guarantee a trailing slash.
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let http = reqwest::Client::builder()
            .timeout(CALL_TIMEOUT)
            .user_agent("conwrt-maas/0.1")
            .build()?;
        Ok(Self {
            base,
            credentials: None,
            insecure_http: false,
            vm_host_id: vm_host_id.to_string(),
            http,
        })
    }

    /// Authenticate with a MAAS API key
    /// (`consumer_key:token:secret`). Every request then carries a
    /// fresh OAuth1 PLAINTEXT header (per-call nonce and timestamp).
    pub fn with_api_key(mut self, api_key: &str) -> Result<Self, MaasHttpError> {
        self.credentials = Some(MaasCredentials::parse(api_key)?);
        Ok(self)
    }

    /// Explicitly allow sending credentials over `http://` (RFC 5849
    /// §3.4.4 wants TLS; this is for isolated lab regions only).
    #[must_use]
    pub fn allow_insecure_http(mut self) -> Self {
        self.insecure_http = true;
        self
    }

    fn machine_url(&self, system_id: &str) -> reqwest::Url {
        self.base
            .join(&format!("machines/{system_id}/"))
            .expect("system_id joined onto a valid base")
    }

    fn machines_url(&self) -> reqwest::Url {
        self.base.join("machines/").expect("valid base")
    }

    fn compose_url(&self) -> reqwest::Url {
        self.base
            .join(&format!("vm-hosts/{}/op-compose", self.vm_host_id))
            .expect("valid base")
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, MaasHttpError> {
        let req = match &self.credentials {
            Some(creds) => {
                if self.base.scheme() != "https" && !self.insecure_http {
                    return Err(MaasHttpError::InsecureTransport(self.base.to_string()));
                }
                req.header("Authorization", fresh_oauth1_header(creds))
            }
            None => req,
        };
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let body = body.chars().take(300).collect();
            return Err(MaasHttpError::Api { status, body });
        }
        Ok(resp)
    }

    async fn machine_from(&self, resp: reqwest::Response) -> Result<MachineRecord, MaasHttpError> {
        let json = resp.json::<MachineJson>().await?;
        json.into_record()
    }
}

/// OAuth1 PLAINTEXT header for MAAS token mode: the consumer secret is
/// empty, so the signature is `&{secret}` (NOT `{secret}&`), and every
/// request carries its own nonce and timestamp. HMAC-SHA1 signing lands
/// with the live-validation round if the region requires it.
#[must_use]
pub fn oauth1_header(creds: &MaasCredentials, nonce: &str, timestamp: u64) -> String {
    format!(
        "OAuth oauth_version=\"1.0\", oauth_signature_method=\"PLAINTEXT\", oauth_consumer_key=\"{}\", oauth_token=\"{}\", oauth_signature=\"&{}\", oauth_timestamp=\"{timestamp}\", oauth_nonce=\"{nonce}\"",
        creds.consumer_key, creds.token, creds.secret
    )
}

/// Per-request header with a fresh nonce (monotonic counter + nanos —
/// unique within and across processes on one host) and timestamp.
fn fresh_oauth1_header(creds: &MaasCredentials) -> String {
    static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    oauth1_header(creds, &format!("conwrt-{nanos}-{n}"), timestamp)
}

impl MaasClient for HttpMaasClient {
    type Error = MaasHttpError;

    async fn compose(&mut self, spec: &VmSpec) -> Result<MachineRecord, Self::Error> {
        let resp = self
            .send(self.http.post(self.compose_url()).form(&[
                ("hostname", spec.name.clone()),
                ("cores", spec.cores.to_string()),
                ("memory", spec.memory_mib.to_string()),
                (
                    "storage",
                    format!("{}:{}(rootfs)", spec.name, spec.disk_gib),
                ),
            ]))
            .await?;
        self.machine_from(resp).await
    }

    async fn machines(&mut self) -> Result<Vec<MachineRecord>, Self::Error> {
        let resp = self.send(self.http.get(self.machines_url())).await?;
        let json = resp.json::<Vec<MachineJson>>().await?;
        json.into_iter()
            .map(MachineJson::into_record)
            .collect::<Result<Vec<_>, _>>()
    }

    async fn machine(&mut self, system_id: &str) -> Result<MachineRecord, Self::Error> {
        let resp = self
            .send(self.http.get(self.machine_url(system_id)))
            .await?;
        self.machine_from(resp).await
    }

    async fn allocate(&mut self, system_id: &str) -> Result<(), Self::Error> {
        // `system_id` is not a supported allocate selector; allocate by
        // the machine's (unique) hostname via the documented `name` form
        // constraint, then verify the region allocated the SAME machine.
        let target = self.machine(system_id).await?;
        let resp = self
            .send(
                self.http
                    .post(self.machines_url())
                    .query(&[("op", "allocate")])
                    .form(&[("name", target.hostname.clone())]),
            )
            .await?;
        let allocated = self.machine_from(resp).await?;
        if allocated.system_id != system_id {
            return Err(MaasHttpError::AllocateMismatch {
                requested: system_id.to_string(),
                allocated: allocated.system_id,
            });
        }
        Ok(())
    }

    async fn deploy(&mut self, system_id: &str) -> Result<(), Self::Error> {
        self.send(
            self.http
                .post(self.machine_url(system_id))
                .query(&[("op", "deploy")]),
        )
        .await?;
        Ok(())
    }

    async fn release(&mut self, system_id: &str) -> Result<(), Self::Error> {
        self.send(
            self.http
                .post(self.machine_url(system_id))
                .query(&[("op", "release")]),
        )
        .await?;
        Ok(())
    }

    async fn delete(&mut self, system_id: &str) -> Result<(), Self::Error> {
        self.send(self.http.delete(self.machine_url(system_id)))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conwrt_maas::provider::VmSpec;
    use httpmock::prelude::*;
    use serde_json::json;

    fn spec() -> VmSpec {
        VmSpec {
            name: "lab-vm-1".into(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
        }
    }

    fn machine_json(id: &str, status: &str) -> serde_json::Value {
        json!({
            "system_id": id,
            "hostname": format!("vm-{id}"),
            "status_name": status,
        })
    }

    #[tokio::test]
    async fn compose_posts_documented_fields_to_op_compose() {
        let server = MockServer::start_async().await;
        let compose = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/vm-hosts/1/op-compose")
                    .body_contains("cores=2")
                    .body_contains("memory=2048")
                    .body_contains("hostname=lab-vm-1")
                    .body_contains("storage=lab-vm-1%3A20%28rootfs%29");
                then.status(200).json_body(machine_json("sys-9", "New"));
            })
            .await;

        let mut client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        let rec = client.compose(&spec()).await.unwrap();

        compose.assert_async().await;
        assert_eq!(rec.system_id, "sys-9");
        assert_eq!(rec.state, MachineState::New);
    }

    #[tokio::test]
    async fn machine_gets_and_parses_status_name() {
        let server = MockServer::start_async().await;
        let get = server
            .mock_async(|when, then| {
                when.method(GET).path("/MAAS/api/2.0/machines/sys-9/");
                then.status(200)
                    .json_body(machine_json("sys-9", "Failed commissioning"));
            })
            .await;

        let mut client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        let rec = client.machine("sys-9").await.unwrap();

        get.assert_async().await;
        assert_eq!(rec.state, MachineState::FailedCommissioning);
    }

    #[tokio::test]
    async fn operations_hit_their_ops_and_verbs() {
        let server = MockServer::start_async().await;
        // allocate's internal hostname lookup (no direct assertion)
        let _machine_lookup = server
            .mock_async(|when, then| {
                when.method(GET).path("/MAAS/api/2.0/machines/sys-1/");
                then.status(200).json_body(machine_json("sys-1", "Ready"));
            })
            .await;
        let allocate = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/")
                    .query_param("op", "allocate")
                    .body_contains("name=vm-sys-1");
                then.status(200)
                    .json_body(machine_json("sys-1", "Allocated"));
            })
            .await;
        let deploy = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/sys-1/")
                    .query_param("op", "deploy");
                then.status(200).json_body(json!({}));
            })
            .await;
        let release = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/sys-1/")
                    .query_param("op", "release");
                then.status(200).json_body(json!({}));
            })
            .await;
        let delete = server
            .mock_async(|when, then| {
                when.method(DELETE).path("/MAAS/api/2.0/machines/sys-1/");
                then.status(200).json_body(json!({}));
            })
            .await;

        let mut client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        client.allocate("sys-1").await.unwrap();
        client.deploy("sys-1").await.unwrap();
        client.release("sys-1").await.unwrap();
        client.delete("sys-1").await.unwrap();

        allocate.assert_async().await;
        deploy.assert_async().await;
        release.assert_async().await;
        delete.assert_async().await;
    }

    #[tokio::test]
    async fn machines_lists_all_records() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/MAAS/api/2.0/machines/");
                then.status(200).json_body(json!([
                    machine_json("sys-1", "Ready"),
                    machine_json("sys-2", "Deployed"),
                ]));
            })
            .await;

        let mut client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        let all = client.machines().await.unwrap();

        assert_eq!(all.len(), 2);
        assert_eq!(all[0].state, MachineState::Ready);
        assert_eq!(all[1].state, MachineState::Deployed);
    }

    #[tokio::test]
    async fn api_error_surfaces_status_and_body() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/MAAS/api/2.0/machines/nope/");
                then.status(404).body("Not Found");
            })
            .await;

        let mut client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        let err = client.machine("nope").await.unwrap_err();

        match err {
            MaasHttpError::Api { status, body } => {
                assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
                assert!(body.contains("Not Found"));
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_key_sends_oauth_header_on_every_call_over_insecure_opt_in() {
        // httpmock 0.7 matches exact header values only; the nonce and
        // timestamp vary per call, so per-call FIELD correctness is
        // pinned by the oauth1_header unit test below — this proves the
        // header is attached on every request and the http opt-in works.
        let server = MockServer::start_async().await;
        let get = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/MAAS/api/2.0/machines/sys-1/")
                    .header_exists("Authorization");
                then.status(200).json_body(machine_json("sys-1", "Ready"));
            })
            .await;

        let mut client = HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1")
            .unwrap()
            .with_api_key("ck:tok:sec")
            .expect("api key parses")
            .allow_insecure_http();
        client.machine("sys-1").await.unwrap();
        client.machine("sys-1").await.unwrap();
        get.assert_hits_async(2).await;
    }

    #[tokio::test]
    async fn api_key_over_http_without_opt_in_is_refused() {
        let server = MockServer::start_async().await;
        let mut client = HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1")
            .unwrap()
            .with_api_key("ck:tok:sec")
            .expect("api key parses");
        let err = client.machine("sys-1").await.unwrap_err();
        assert!(
            matches!(err, MaasHttpError::InsecureTransport { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn malformed_api_key_is_refused() {
        let server = MockServer::start_async().await;
        assert!(
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1")
                .unwrap()
                .with_api_key("not-a-triple")
                .is_err()
        );
    }

    #[test]
    fn oauth1_header_has_inverted_plaintext_signature_nonce_and_timestamp() {
        let creds = MaasCredentials {
            consumer_key: "ck".into(),
            token: "tok".into(),
            secret: "sec".into(),
        };
        let h = oauth1_header(&creds, "nonce-7", 1_777_777_777);
        assert!(h.starts_with("OAuth "));
        assert!(h.contains("oauth_signature_method=\"PLAINTEXT\""));
        assert!(h.contains("oauth_consumer_key=\"ck\""));
        assert!(h.contains("oauth_token=\"tok\""));
        // MAAS token mode: empty consumer secret -> "&{secret}", not "{secret}&"
        assert!(h.contains("oauth_signature=\"&sec\""));
        assert!(h.contains("oauth_nonce=\"nonce-7\""));
        assert!(h.contains("oauth_timestamp=\"1777777777\""));
    }

    #[tokio::test]
    async fn allocate_mismatch_is_an_error_not_a_silent_leak() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/MAAS/api/2.0/machines/sys-1/");
                then.status(200).json_body(machine_json("sys-1", "Ready"));
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/")
                    .query_param("op", "allocate")
                    .body_contains("name=vm-sys-1");
                // MAAS allocated a DIFFERENT machine than the composed one
                then.status(200)
                    .json_body(machine_json("sys-OTHER", "Allocated"));
            })
            .await;

        let mut client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        let err = client.allocate("sys-1").await.unwrap_err();
        assert!(
            matches!(err, MaasHttpError::AllocateMismatch { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn provider_drives_the_full_verb_chain_over_http() {
        // machine() always reports Ready: stage-1 (await Ready) passes on
        // the first poll, allocate+deploy fire, and stage-2 (await
        // Deployed) hits the bounded-poll guard. One static body cannot
        // sequence two lifecycle answers (httpmock responses are static),
        // so the poll-bound error IS the expected terminal event — it
        // proves the full verb chain AND bounded polling over real HTTP.
        let server = MockServer::start_async().await;
        let compose = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/vm-hosts/1/op-compose");
                then.status(200)
                    .json_body(machine_json("sys-1", "Commissioning"));
            })
            .await;
        // allocate's internal hostname lookup (no direct assertion)
        let machine = server
            .mock_async(|when, then| {
                when.method(GET).path("/MAAS/api/2.0/machines/sys-1/");
                then.status(200).json_body(machine_json("sys-1", "Ready"));
            })
            .await;
        let allocate = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/")
                    .query_param("op", "allocate")
                    .body_contains("name=vm-sys-1");
                then.status(200)
                    .json_body(machine_json("sys-1", "Allocated"));
            })
            .await;
        let deploy = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/sys-1/")
                    .query_param("op", "deploy");
                then.status(200).json_body(json!({}));
            })
            .await;

        use conwrt_core::Time;
        use conwrt_maas::provider::ComputeError;
        use conwrt_maas::provider::ComputeProvider;
        struct NoTime;
        impl Time for NoTime {
            async fn sleep_ms(&mut self, _ms: u64) {}
        }

        let client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        let mut provider =
            conwrt_maas::provider::MaasProvider::new(client, NoTime).with_polling(0, 60);

        let err = provider.create_vm(&spec()).await.unwrap_err();
        assert!(matches!(
            err,
            ComputeError::NeverReached {
                wanted: "Deployed",
                ..
            }
        ));

        compose.assert_hits_async(1).await;
        // 1 (await Ready) + 1 (allocate's name lookup) + 60 (bounded await Deployed)
        machine.assert_hits_async(62).await;
        allocate.assert_hits_async(1).await;
        deploy.assert_hits_async(1).await;
    }

    #[tokio::test]
    async fn provider_destroys_ready_machine_over_http() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/MAAS/api/2.0/machines/sys-1/");
                then.status(200).json_body(machine_json("sys-1", "Ready"));
            })
            .await;
        let release = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/sys-1/")
                    .query_param("op", "release");
                then.status(200).json_body(json!({}));
            })
            .await;
        let delete = server
            .mock_async(|when, then| {
                when.method(DELETE).path("/MAAS/api/2.0/machines/sys-1/");
                then.status(200).json_body(json!({}));
            })
            .await;

        use conwrt_core::Time;
        use conwrt_maas::provider::ComputeProvider;
        struct NoTime;
        impl Time for NoTime {
            async fn sleep_ms(&mut self, _ms: u64) {}
        }

        let client =
            HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1").unwrap();
        let mut provider = conwrt_maas::provider::MaasProvider::new(client, NoTime);

        provider.destroy_vm("sys-1").await.unwrap();

        release.assert_hits_async(0).await; // Ready machines skip release
        delete.assert_hits_async(1).await;
    }
}
