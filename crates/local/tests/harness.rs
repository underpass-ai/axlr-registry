//! The harness end to end on 127.0.0.1:0: a publisher uploads a skill at
//! 1.0.0 and 1.1.0 and a tool, signing as the CLI signs, and the catalog is
//! read back as the console reads it, its index signature verified.

use std::path::Path;
use std::sync::Arc;

use axlr_registry_cli::{PublishClient, SignatureFile, ToolDir, UploadRequest};
use base64::Engine as _;
use clap::Parser as _;
use ed25519_dalek::SigningKey;
use registry_domain::{Digest, Index, IndexSignature, RegistryPublicKey, ToolName, Version};
use registry_local::{IndexKey, LocalOptions, LocalRegistry};
use registry_runner::Confinement;
use tokio::task::JoinHandle;

struct Harness {
    base: String,
    registry: Arc<LocalRegistry>,
    server: JoinHandle<Result<(), registry_local::LocalError>>,
    key_dir: tempfile::TempDir,
    key: SigningKey,
    catalog: reqwest::Client,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn harness(auto_approve: bool, confinement: Confinement) -> Harness {
    let key_dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[21; 32]);
    let public = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
    let options = LocalOptions::try_parse_from([
        "axlr-registry-local",
        "--listen",
        "127.0.0.1:0",
        "--key-dir",
        key_dir.path().to_str().unwrap(),
        "--publisher-id",
        "acme",
        "--publisher-key",
        &public,
        "--namespaces",
        "acme_*",
        &format!("--auto-approve={auto_approve}"),
    ])
    .unwrap();
    let (server, registry) = registry_local::start(&options, confinement).await.unwrap();
    let base = server.base_url();
    let banner = registry_local::banner(&options, &server, &registry);
    assert!(banner.contains(&format!("base_url    {base}")), "{banner}");
    assert!(banner.contains(&format!("public_key  {}", registry.key().public_key_line())), "{banner}");
    assert!(banner.contains("acme (key id "), "{banner}");
    let server = tokio::spawn(server.serve(Arc::clone(&registry)));
    let catalog = reqwest::Client::builder().user_agent("AXLR-catalog").build().unwrap();
    Harness { base, registry, server, key_dir, key, catalog }
}

impl Harness {
    fn client(&self) -> PublishClient {
        PublishClient::new(&self.base, self.key.clone()).unwrap()
    }

    /// Signs and uploads the directory as `axlr-registry publisher upload` does.
    async fn upload(&self, dir: &Path) -> serde_json::Value {
        let tool = ToolDir::load(dir).unwrap();
        let signature = SignatureFile::sign(&self.key, tool.bundle().bundle_digest());
        self.client().upload(&UploadRequest::new(&tool, signature)).await.unwrap()
    }

    async fn status(&self, name: &str, version: &str) -> serde_json::Value {
        self.client().status(&ToolName::parse(name).unwrap(), &Version::parse(version).unwrap()).await.unwrap()
    }

    async fn get(&self, path: &str) -> (u16, Vec<u8>) {
        let response = self.catalog.get(format!("{}{path}", self.base)).send().await.unwrap();
        (response.status().as_u16(), response.bytes().await.unwrap().to_vec())
    }

    async fn post(&self, path: &str, body: &str) -> (u16, serde_json::Value) {
        let response = self.catalog.post(format!("{}{path}", self.base)).body(body.to_owned()).send().await.unwrap();
        (response.status().as_u16(), response.json().await.unwrap())
    }

    /// The published index, its signature checked against `registry.pub`
    /// as the console checks it.
    async fn index(&self) -> Index {
        let (status, index) = self.get("/index.json").await;
        assert_eq!(status, 200);
        let (status, signature) = self.get("/index.json.minisig").await;
        assert_eq!(status, 200);
        let public = std::fs::read_to_string(self.key_dir.path().join(IndexKey::PUBLIC_FILE)).unwrap();
        let public = RegistryPublicKey::parse(&public).unwrap();
        let signature = IndexSignature::parse(std::str::from_utf8(&signature).unwrap()).unwrap();
        assert!(signature.trusted_comment().ends_with("\tfile:index.json\tprehashed"), "{}", signature.trusted_comment());
        signature.verify(&public, &index).unwrap();
        serde_json::from_slice(&index).unwrap()
    }
}

/// A skill directory as the console's `/skills publish` builds it.
fn write_skill(dir: &Path, version: &str, step: &str) {
    let manifest = serde_json::json!({
        "kind": "skill", "name": "acme_triage",
        "description": "Triage a production incident from its logs: timeline, blast radius, first hypothesis, next check.",
        "files": ["SKILL.md", "checklist.md"], "tools": ["local_read", "local_search", "github/list_issues"],
        "catalog": {"version": version, "category": "programming", "tags": ["sre", "incident"], "license": "MIT", "source": "original"}
    });
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let skill_md = format!(
        "---\nname: acme_triage\ndescription: Triage a production incident.\n---\n# Incident triage\n\n{step}\n\nWork through [the checklist](checklist.md).\n"
    );
    std::fs::write(dir.join("SKILL.md"), skill_md).unwrap();
    std::fs::write(dir.join("checklist.md"), "- timeline\n- blast radius\n- first hypothesis\n").unwrap();
    let tests = r#"[{"name": "starts_from_logs", "prompt": "The API answers 502 since 10:00; logs are in logs/api.log", "expect": {"tools": ["local_read"], "answer_contains": ["timeline"]}}]"#;
    std::fs::write(dir.join("tests.json"), tests).unwrap();
}

/// A tool directory; `tests` adds a `tests.json`.
fn write_tool(dir: &Path, tests: bool) {
    let manifest = serde_json::json!({
        "name": "acme_count", "description": "Count items.", "input_schema": {"type": "object"}, "program": "python3",
        "args": ["count.py"], "files": ["count.py"], "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}
    });
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
    std::fs::write(dir.join("count.py"), "import json, sys\nprint(json.dumps({'n': len(json.load(sys.stdin)['items'])}))\n").unwrap();
    if tests {
        std::fs::write(dir.join("tests.json"), r#"[{"name": "two", "input": {"items": [1, 2]}, "expect": {"stdout_json": {"n": 2}}}]"#)
            .unwrap();
    }
}

#[tokio::test]
async fn skills_are_published_signed_and_served_beside_tools() {
    let h = harness(true, Confinement::Unavailable("tools are not run in this test".into())).await;
    let empty = h.index().await;
    assert!(empty.tools.is_empty() && empty.skills.is_empty(), "the harness starts with an empty signed index");
    assert_eq!(empty.catalog, "local");

    let skill = tempfile::tempdir().unwrap();
    write_skill(skill.path(), "1.0.0", "Build the timeline first.");
    let uploaded = h.upload(skill.path()).await;
    assert_eq!(uploaded["status"], "scanned", "{uploaded}");
    let status = h.status("acme_triage", "1.0.0").await;
    assert_eq!(
        (status["kind"].as_str(), status["status"].as_str(), status["tests_passed"].as_bool()),
        (Some("skill"), Some("approved"), Some(true))
    );
    write_skill(skill.path(), "1.1.0", "Build the timeline first, then the blast radius.");
    assert_eq!(h.upload(skill.path()).await["status"], "scanned");

    let tool = tempfile::tempdir().unwrap();
    write_tool(tool.path(), false);
    assert_eq!(h.upload(tool.path()).await["status"], "scanned");
    let status = h.status("acme_count", "1.0.0").await;
    assert_eq!((status["kind"].as_str(), status["status"].as_str()), (Some("tool"), Some("scanned")), "{status}");
    assert_eq!(status["failed_tests"], serde_json::json!(["tests.json"]), "a tool without tests stays unapprovable");

    let index = h.index().await;
    assert!(index.tools.is_empty(), "an untested tool was published");
    let versions: Vec<&str> = index.skills.iter().map(|s| s.version.as_str()).collect();
    assert_eq!(versions, ["1.0.0", "1.1.0"]);
    for entry in &index.skills {
        assert_eq!((entry.publisher.as_str(), entry.reviewer.as_str()), ("acme", LocalRegistry::REVIEWER));
        let (status, manifest) = h.get(&format!("/{}", entry.manifest)).await;
        assert_eq!(status, 200);
        assert_eq!(Digest::of(&manifest).to_string(), entry.manifest_sha256);
        for (file, digest) in &entry.files {
            let (status, bytes) = h.get(&format!("/skills/acme_triage/{}/{file}", entry.version)).await;
            assert_eq!((status, Digest::of(&bytes).to_string()), (200, digest.clone()), "{file}");
        }
        let (status, _) = h.get(&format!("/skills/acme_triage/{}/tests.json", entry.version)).await;
        assert_eq!(status, 404, "tests.json was published");
    }
    let (_, skill_md) = h.get("/skills/acme_triage/1.1.0/SKILL.md").await;
    assert!(String::from_utf8(skill_md).unwrap().contains("then the blast radius"));
    assert_eq!(h.get("/tools/acme_count/1.0.0/count.py").await.0, 404, "an unapproved file was served");
    assert_eq!(h.get("/nothing").await.0, 404);
    let anonymous = reqwest::get(format!("{}/index.json", h.base)).await.unwrap();
    assert_eq!(anonymous.status().as_u16(), 403, "the catalog answered a client that is not AXLR");

    let (status, body) = h.post("/local/yank/acme_triage/1.0.0", r#"{"reason": "the timeline step was wrong"}"#).await;
    assert_eq!((status, body["status"].as_str()), (200, Some("yanked")), "{body}");
    let index = h.index().await;
    assert_eq!(index.skills.iter().map(|s| s.version.as_str()).collect::<Vec<_>>(), ["1.1.0"]);
    assert_eq!((index.revocations[0].name.as_str(), index.revocations[0].reason.as_str()), ("acme_triage", "the timeline step was wrong"));
    let (status, _) = h.post("/local/yank/acme_triage/1.1.0", "{}").await;
    assert_eq!(status, 400, "a yank without a reason");
    let (status, _) = h.post("/local/yank/acme_triage/1.0.0", r#"{"reason": "again"}"#).await;
    assert_eq!(status, 409, "yanked twice");
}

#[tokio::test]
async fn manual_approval_and_a_tool_under_bubblewrap() {
    let h = harness(false, Confinement::detect()).await;
    let skill = tempfile::tempdir().unwrap();
    write_skill(skill.path(), "1.0.0", "Build the timeline first.");
    h.upload(skill.path()).await;
    let status = h.status("acme_triage", "1.0.0").await;
    assert_eq!((status["status"].as_str(), status["tests_passed"].as_bool()), (Some("scanned"), Some(true)), "{status}");
    assert!(h.index().await.skills.is_empty(), "a skill was approved without a reviewer");
    let (status, body) = h.post("/local/approve/acme_triage/1.0.0", "").await;
    assert_eq!((status, body["status"].as_str()), (200, Some("approved")), "{body}");
    assert_eq!(h.index().await.skills.len(), 1);
    let (status, _) = h.post("/local/approve/acme_triage/1.0.0", "").await;
    assert_eq!(status, 409, "approved twice");
    let (status, _) = h.post("/local/approve/acme_nothing/1.0.0", "").await;
    assert_eq!(status, 404);

    let tool = tempfile::tempdir().unwrap();
    write_tool(tool.path(), true);
    h.upload(tool.path()).await;
    let report = h.registry.report(&ToolName::parse("acme_count").unwrap(), &Version::parse("1.0.0").unwrap()).await.unwrap();
    if *h.registry.confinement() != Confinement::Bubblewrap {
        assert_eq!(report.failed(), ["sandbox"], "a tool ran unconfined");
        return;
    }
    assert!(report.all_passed(), "{:?}", report.failed());
    let (status, _) = h.post("/local/approve/acme_count/1.0.0", r#"{"reason": "counts"}"#).await;
    assert_eq!(status, 200);
    let index = h.index().await;
    assert_eq!((index.tools.len(), index.skills.len()), (1, 1));
    let (status, code) = h.get("/tools/acme_count/1.0.0/count.py").await;
    assert_eq!((status, Digest::of(&code).to_string()), (200, index.tools[0].files["count.py"].clone()));
}

#[tokio::test]
async fn refuses_to_listen_off_the_loopback() {
    let key_dir = tempfile::tempdir().unwrap();
    let options =
        LocalOptions::try_parse_from(["axlr-registry-local", "--listen", "0.0.0.0:0", "--key-dir", key_dir.path().to_str().unwrap()])
            .unwrap();
    let refused = registry_local::start(&options, Confinement::Environment).await.unwrap_err();
    assert!(refused.to_string().contains("loopback"), "{refused}");
    let options =
        LocalOptions::try_parse_from(["axlr-registry-local", "--listen", "127.0.0.1:0", "--key-dir", key_dir.path().to_str().unwrap()])
            .unwrap();
    let (server, registry) = registry_local::start(&options, Confinement::Environment).await.unwrap();
    let banner = registry_local::banner(&options, &server, &registry);
    assert!(banner.contains("none registered") && banner.contains("tools run unconfined") && banner.contains("automatic"), "{banner}");
}
