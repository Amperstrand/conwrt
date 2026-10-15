//! HTTP [`MaasClient`] over `reqwest` — the production MAAS path for the
//! [`conwrt_maas::provider::MaasProvider`] (issue #169, milestones M5).
//!
//! Contract mirrors the region API 2.0 shapes the provider needs:
//!
//! | Provider op        | Region call                             |
//! |--------------------|-----------------------------------------|
//! | `compose`          | `POST /vm-hosts/{id}/compose/`          |
//! | `machines`         | `GET /machines/`                        |
//! | `machine`          | `GET /machines/{system_id}/`            |
//! | `allocate`         | `POST /machines/?op=allocate`           |
//! | `deploy`           | `POST /machines/{system_id}/?op=deploy` |
//! | `release`          | `POST /machines/{system_id}/?op=release`|
//! | `delete`           | `DELETE /machines/{system_id}/`         |
//!
//! Tests run against `httpmock` (the `conwrt-image` pattern — no real
//! network calls); the exact auth scheme and any parameter drift get
//! pinned when the client meets the live region (owner-gated live
//! validation, see issue #169 follow-ups).

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
}

/// reqwest-backed [`MaasClient`]. Clone-safe (pooled HTTP client).
#[derive(Debug, Clone)]
pub struct HttpMaasClient {
    base: reqwest::Url,
    auth: Option<String>,
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
            auth: None,
            vm_host_id: vm_host_id.to_string(),
            http,
        })
    }

    /// Attach a raw `Authorization` header value. The final scheme
    /// (OAuth1 HMAC-SHA1 signing vs PLAINTEXT-over-TLS vs bearer) is
    /// pinned against the live region; see [`oauth1_plaintext`].
    #[must_use]
    pub fn with_authorization(mut self, header_value: String) -> Self {
        self.auth = Some(header_value);
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
            .join(&format!("vm-hosts/{}/compose/", self.vm_host_id))
            .expect("valid base")
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, MaasHttpError> {
        let req = match &self.auth {
            Some(v) => req.header("Authorization", v),
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

/// OAuth1 PLAINTEXT header value for a MAAS API key
/// (`consumer_key:token:secret` triple) over TLS — the scheme MAAS's own
/// client accepts in token mode. HMAC-SHA1 signing lands with live
/// validation if the region requires it.
#[must_use]
pub fn oauth1_plaintext(consumer_key: &str, token: &str, secret: &str) -> String {
    format!(
        "OAuth oauth_version=\"1.0\", oauth_signature_method=\"PLAINTEXT\", oauth_consumer_key=\"{consumer_key}\", oauth_token=\"{token}\", oauth_signature=\"{secret}&\""
    )
}

impl MaasClient for HttpMaasClient {
    type Error = MaasHttpError;

    async fn compose(&mut self, spec: &VmSpec) -> Result<MachineRecord, Self::Error> {
        let resp = self
            .send(self.http.post(self.compose_url()).form(&[
                ("cores", spec.cores.to_string()),
                ("memory", spec.memory_mib.to_string()),
                ("disks", format!("{}:{}", spec.disk_gib, spec.name)),
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
        self.send(
            self.http
                .post(self.machines_url())
                .query(&[("op", "allocate"), ("system_id", system_id)]),
        )
        .await?;
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
    async fn compose_posts_form_to_vm_host_endpoint() {
        let server = MockServer::start_async().await;
        let compose = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/vm-hosts/1/compose/")
                    .body_contains("cores=2");
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
        let allocate = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/MAAS/api/2.0/machines/")
                    .query_param("op", "allocate")
                    .query_param("system_id", "sys-1");
                then.status(200).json_body(json!({}));
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
    async fn authorization_header_is_sent_when_attached() {
        let server = MockServer::start_async().await;
        let get = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/MAAS/api/2.0/machines/sys-1/")
                    .header("Authorization", "OAuth oauth_token=\"t\"");
                then.status(200).json_body(machine_json("sys-1", "Ready"));
            })
            .await;

        let mut client = HttpMaasClient::new(&format!("{}/MAAS/api/2.0", server.base_url()), "1")
            .unwrap()
            .with_authorization("OAuth oauth_token=\"t\"".into());
        client.machine("sys-1").await.unwrap();
        get.assert_async().await;
    }

    #[tokio::test]
    async fn oauth1_plaintext_builds_the_documented_shape() {
        let h = oauth1_plaintext("ck", "tok", "sec");
        assert!(h.starts_with("OAuth "));
        assert!(h.contains("oauth_signature_method=\"PLAINTEXT\""));
        assert!(h.contains("oauth_consumer_key=\"ck\""));
        assert!(h.contains("oauth_token=\"tok\""));
        assert!(h.ends_with("oauth_signature=\"sec&\""));
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
                when.method(POST).path("/MAAS/api/2.0/vm-hosts/1/compose/");
                then.status(200)
                    .json_body(machine_json("sys-1", "Commissioning"));
            })
            .await;
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
                    .query_param("system_id", "sys-1");
                then.status(200).json_body(json!({}));
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
        machine.assert_hits_async(61).await; // 1 (await Ready) + 60 (bounded await Deployed)
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
