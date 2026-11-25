use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const SIGNATURE: &str = "application/vnd.microsign.signature.v1+json";
const PAYLOAD_TYPE: &str = "application/vnd.microsign.image-signature.payload.v1+json";
const SOURCE: &str = "build/image";
const DESTINATION: &str = "release/image";
const CHANGED: &str = "changed/image";

#[test]
fn promotes_the_same_signature_for_each_algorithm() -> Result<()> {
    for (option, algorithm) in [
        (None, "ML-DSA-65"),
        (Some("ed25519"), "Ed25519"),
        (Some("ecdsa-p256"), "ECDSA-P256-SHA256"),
    ] {
        exercise_workflow(option, algorithm)
            .with_context(|| format!("testing {algorithm} promotion"))?;
    }
    Ok(())
}

fn exercise_workflow(option: Option<&str>, algorithm: &str) -> Result<()> {
    let registry = TestRegistry::start()?;
    let directory = tempfile::tempdir()?;
    let private_key = directory.path().join("private.pem");
    let public_key = directory.path().join("public.pem");
    let bundle = directory.path().join("signature.json");
    let image = registry.image(SOURCE);
    generate_key(option, &private_key, &public_key)?;
    assert_failure(
        sign_command(option, &private_key, &bundle, &image)
            .arg("--require-digest")
            .output()?,
        "digest-pinned image reference",
    );
    assert!(!bundle.exists());
    assert_success(sign_command(option, &private_key, &bundle, &image).output()?);
    let signature = fs::read(&bundle)?;
    let envelope: Value = serde_json::from_slice(&signature)?;
    assert_eq!(envelope["payloadType"], PAYLOAD_TYPE);
    let payload = envelope["payload"]
        .as_str()
        .context("missing signed payload")?;
    let metadata: Value = serde_json::from_slice(&STANDARD.decode(payload)?)?;
    assert_eq!(metadata["algorithm"], algorithm);
    let (source_digest, source_attachment) = registry.attachment(SOURCE, &signature);
    fs::remove_file(private_key)?;

    let writes = registry.state.lock().unwrap().write_requests;
    let verify =
        |target: &str| bundle_command("verify", option, &bundle, &public_key, target).output();
    assert_success(verify(&registry.pinned_image(DESTINATION))?);
    assert_failure(
        verify(&registry.pinned_image(CHANGED))?,
        "but the target resolves to",
    );
    assert_failure(
        verify(&registry.image(DESTINATION))?,
        "digest-pinned image reference",
    );
    assert_eq!(registry.state.lock().unwrap().write_requests, writes);

    let reuse = |repository| {
        bundle_command(
            "reuse",
            option,
            &bundle,
            &public_key,
            &registry.image(repository),
        )
        .arg("--native-referrers-only")
        .output()
    };

    for _ in 0..2 {
        assert_success(reuse(DESTINATION)?);
        let (destination_digest, destination_attachment) =
            registry.attachment(DESTINATION, &signature);
        assert_eq!(destination_digest, source_digest);
        assert_eq!(destination_attachment, source_attachment);
        assert_eq!(fs::read(&bundle)?, signature);
    }

    let writes = registry.state.lock().unwrap().write_requests;
    assert_failure(reuse(CHANGED)?, "but the target resolves to");
    assert_eq!(registry.state.lock().unwrap().write_requests, writes);
    Ok(())
}

#[test]
fn referrers_fallback_merges_a_concurrent_update() -> Result<()> {
    let registry = TestRegistry::start_with_referrers(false)?;
    let directory = tempfile::tempdir()?;
    let private = directory.path().join("private.pem");
    let public = directory.path().join("public.pem");
    let bundle = directory.path().join("signature.json");
    let image = registry.pinned_image(SOURCE);
    generate_key(None, &private, &public)?;

    assert_failure(
        sign_command(None, &private, &bundle, &image)
            .args(["--require-digest", "--native-referrers-only"])
            .output()?,
        "required native OCI referrers API",
    );
    assert!(bundle.is_file());
    assert_eq!(registry.state.lock().unwrap().write_requests, 0);

    for _ in 0..2 {
        assert_success(bundle_command("reuse", None, &bundle, &public, &image).output()?);
    }
    let (attachment, _) = registry.attachment(SOURCE, &fs::read(bundle)?);
    let state = registry.state.lock().unwrap();
    let repository = &state.repositories[SOURCE];
    let raw = repository
        .referrers_index
        .as_ref()
        .context("missing fallback index")?;
    let index: Value = serde_json::from_slice(raw)?;
    assert_eq!(index["annotations"]["example.fixture"], "preserved");
    let entries = index["manifests"]
        .as_array()
        .context("missing fallback entries")?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["digest"], digest(b"another attachment"));
    assert_eq!(entries[1]["digest"], attachment);
    assert_eq!(repository.referrers_puts, 2);
    Ok(())
}

#[test]
fn sign_rejects_an_invalid_descriptor_before_creating_a_bundle() -> Result<()> {
    let registry = TestRegistry::start()?;
    let directory = tempfile::tempdir()?;
    let private = directory.path().join("private.pem");
    let public = directory.path().join("public.pem");
    let bundle = directory.path().join("signature.json");
    generate_key(None, &private, &public)?;
    {
        let mut state = registry.state.lock().unwrap();
        let repository = state.repositories.get_mut(SOURCE).unwrap();
        let mut manifest: Value = serde_json::from_slice(&repository.image)?;
        manifest["config"]["size"] = json!(-1);
        repository.image = serde_json::to_vec(&manifest)?;
    }
    assert_failure(
        sign_command(None, &private, &bundle, &registry.pinned_image(SOURCE)).output()?,
        "invalid image config descriptor",
    );
    assert!(!bundle.exists());
    assert_eq!(registry.state.lock().unwrap().write_requests, 0);
    Ok(())
}

fn generate_key(option: Option<&str>, private_key: &Path, public_key: &Path) -> Result<()> {
    assert_success(
        digestseal("keygen", option)
            .arg("--private-key")
            .arg(private_key)
            .arg("--public-key")
            .arg(public_key)
            .output()?,
    );
    Ok(())
}

fn sign_command(option: Option<&str>, key: &Path, bundle: &Path, image: &str) -> Command {
    let mut command = digestseal("sign", option);
    command
        .arg("--key")
        .arg(key)
        .arg("--bundle")
        .arg(bundle)
        .arg("--plain-http")
        .arg(image);
    command
}

fn bundle_command(
    operation: &str,
    option: Option<&str>,
    bundle: &Path,
    public_key: &Path,
    image: &str,
) -> Command {
    let mut command = digestseal(operation, option);
    command
        .arg("--bundle")
        .arg(bundle)
        .arg("--public-key")
        .arg(public_key)
        .arg("--plain-http")
        .arg(image);
    command
}

fn digestseal(operation: &str, algorithm: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_digestseal"));
    command
        .arg(operation)
        .env_remove("DIGESTSEAL_REGISTRY_USERNAME")
        .env_remove("DIGESTSEAL_REGISTRY_PASSWORD")
        .env_remove("DIGESTSEAL_REGISTRY_AUTH_HOST")
        .env_remove("DIGESTSEAL_REGISTRY_HOST")
        .env_remove("DIGESTSEAL_REGISTRY_STORAGE_HOST")
        .env_remove("MICROSIGN_REGISTRY_USERNAME")
        .env_remove("MICROSIGN_REGISTRY_PASSWORD")
        .env_remove("MICROSIGN_REGISTRY_AUTH_HOST")
        .env_remove("MICROSIGN_REGISTRY_HOST")
        .env_remove("MICROSIGN_REGISTRY_STORAGE_HOST")
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1");
    if let Some(algorithm) = algorithm {
        command.args(["--algorithm", algorithm]);
    }
    command
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "DigestSeal exited with {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: Output, expected: &str) {
    assert!(!output.status.success());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains(expected), "{diagnostic}");
}

struct TestRegistry {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    server: Option<JoinHandle<()>>,
}

struct State {
    repositories: HashMap<&'static str, Repository>,
    write_requests: usize,
    native_referrers: bool,
}

struct Repository {
    image: Vec<u8>,
    blobs: HashMap<String, Vec<u8>>,
    manifests: HashMap<String, Vec<u8>>,
    referrers_index: Option<Vec<u8>>,
    referrers_puts: usize,
}

impl TestRegistry {
    fn start() -> Result<Self> {
        Self::start_with_referrers(true)
    }

    fn start_with_referrers(native_referrers: bool) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .context("binding the test OCI registry to loopback")?;
        let address = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            repositories: HashMap::from([
                (SOURCE, Repository::new("original")),
                (DESTINATION, Repository::new("original")),
                (CHANGED, Repository::new("changed")),
            ]),
            write_requests: 0,
            native_referrers,
        }));
        let server_state = Arc::clone(&state);
        let server = thread::spawn(move || {
            for connection in listener.incoming() {
                let stream = connection.expect("accepting loopback request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                // A connection closed without a request stops the fixture.
                if reader.read_line(&mut request_line).unwrap() == 0 {
                    break;
                }
                server_state
                    .lock()
                    .unwrap()
                    .handle(reader, &request_line)
                    .unwrap();
            }
        });
        Ok(Self {
            address,
            state,
            server: Some(server),
        })
    }

    fn image(&self, repository: &str) -> String {
        format!("{}/{repository}:latest", self.address)
    }

    fn pinned_image(&self, repository: &str) -> String {
        let state = self.state.lock().unwrap();
        let image_digest = digest(&state.repositories[repository].image);
        format!("{}/{repository}@{image_digest}", self.address)
    }

    fn attachment(&self, repository: &str, signature: &[u8]) -> (String, Vec<u8>) {
        let state = self.state.lock().unwrap();
        let repository = &state.repositories[repository];
        assert_eq!(repository.manifests.len(), 1);
        let (address, raw) = repository.manifests.iter().next().unwrap();
        let attachment: Value = serde_json::from_slice(raw).unwrap();
        let layer = &attachment["layers"][0];
        assert_eq!(address, &digest(raw));
        assert_eq!(attachment["artifactType"], SIGNATURE);
        assert_eq!(attachment["subject"]["digest"], digest(&repository.image));
        assert_eq!(layer["mediaType"], SIGNATURE);
        assert_eq!(layer["digest"], digest(signature));
        assert_eq!(
            repository.blobs[layer["digest"].as_str().unwrap()],
            signature
        );
        (address.clone(), raw.clone())
    }
}

impl Drop for TestRegistry {
    fn drop(&mut self) {
        drop(TcpStream::connect(self.address));
        let result = self.server.take().unwrap().join();
        if !thread::panicking() {
            result.expect("test OCI registry thread panicked");
        }
    }
}

impl Repository {
    fn new(version: &str) -> Self {
        let image = json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest(b"{}"),
                "size": 2,
            },
            "layers": [],
            "annotations": { "org.opencontainers.image.version": version },
        });
        Self {
            image: serde_json::to_vec(&image).unwrap(),
            blobs: HashMap::new(),
            manifests: HashMap::new(),
            referrers_index: None,
            referrers_puts: 0,
        }
    }
}

impl State {
    fn handle(&mut self, mut stream: BufReader<TcpStream>, request_line: &str) -> Result<()> {
        let mut parts = request_line.split_whitespace();
        let method = parts.next().context("missing method")?;
        let target = parts.next().context("missing target")?;
        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            ensure!(
                stream.read_line(&mut line)? > 0,
                "incomplete request headers"
            );
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
            }
        }
        let length = headers
            .get("content-length")
            .map(|length| length.parse())
            .transpose()?
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body)?;
        let mut stream = stream.into_inner();
        let url = Url::parse(&format!("http://localhost{target}"))?;
        let (repository, path) = [SOURCE, DESTINATION, CHANGED]
            .into_iter()
            .find_map(|repository| {
                url.path()
                    .strip_prefix(&format!("/v2/{repository}/"))
                    .map(|path| (repository, path))
            })
            .with_context(|| format!("unexpected registry request: {target}"))?;
        let (kind, reference) = path.split_once('/').context("missing registry reference")?;
        let state = self.repositories.get_mut(repository).unwrap();
        let subject = digest(&state.image);
        let referrers_tag = subject.replace(':', "-");
        if matches!(method, "POST" | "PUT") {
            self.write_requests += 1;
        }
        match (method, kind, reference) {
            ("GET", "manifests", reference) if reference == "latest" || reference == subject => {
                respond(
                    &mut stream,
                    "200 OK",
                    &[
                        ("Content-Type", OCI_MANIFEST),
                        ("Docker-Content-Digest", &subject),
                    ],
                    &state.image,
                )?;
            }
            ("GET", "referrers", reference) if self.native_referrers && reference == subject => {
                let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": []});
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", OCI_INDEX)],
                    &serde_json::to_vec(&index)?,
                )?;
            }
            ("GET", "manifests", reference) if reference == referrers_tag => {
                match &state.referrers_index {
                    Some(raw) => respond(
                        &mut stream,
                        "200 OK",
                        &[("Content-Type", OCI_INDEX), ("ETag", "\"referrers-index\"")],
                        raw,
                    )?,
                    None => respond(&mut stream, "404 Not Found", &[], &[])?,
                }
            }
            ("HEAD", "blobs", digest) if state.blobs.contains_key(digest) => {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Docker-Content-Digest", digest)],
                    &[],
                )?;
            }
            ("HEAD", "blobs", _) => respond(&mut stream, "404 Not Found", &[], &[])?,
            ("POST", "blobs", "uploads/") => {
                let location = format!("/v2/{repository}/blobs/uploads/fixture");
                respond(&mut stream, "202 Accepted", &[("Location", &location)], &[])?;
            }
            ("PUT", "blobs", "uploads/fixture") => {
                let digest = digest(&body);
                ensure!(
                    url.query_pairs()
                        .any(|(name, value)| name == "digest" && value == digest),
                    "incorrect blob digest"
                );
                state.blobs.insert(digest.clone(), body);
                respond(
                    &mut stream,
                    "201 Created",
                    &[("Docker-Content-Digest", &digest)],
                    &[],
                )?;
            }
            ("PUT", "manifests", reference) if reference == referrers_tag => {
                state.referrers_puts += 1;
                if state.referrers_index.is_none() {
                    ensure!(
                        headers.get("if-none-match").map(String::as_str) == Some("*"),
                        "fallback creation must be conditional"
                    );
                    let competing_index = json!({
                        "schemaVersion": 2,
                        "mediaType": OCI_INDEX,
                        "manifests": [{
                            "mediaType": OCI_MANIFEST,
                            "artifactType": SIGNATURE,
                            "size": 18,
                            "digest": digest(b"another attachment"),
                        }],
                        "annotations": { "example.fixture": "preserved" },
                    });
                    state.referrers_index = Some(serde_json::to_vec(&competing_index)?);
                    respond(&mut stream, "412 Precondition Failed", &[], &[])?;
                } else {
                    ensure!(
                        headers.get("if-match").map(String::as_str) == Some("\"referrers-index\""),
                        "fallback update must use the fetched ETag"
                    );
                    state.referrers_index = Some(body);
                    respond(&mut stream, "201 Created", &[], &[])?;
                }
            }
            ("PUT", "manifests", address) => {
                ensure!(address == digest(&body), "incorrect artifact digest");
                let manifest: Value = serde_json::from_slice(&body)?;
                ensure!(
                    manifest["subject"]["digest"] == subject,
                    "incorrect artifact subject"
                );
                for descriptor in [&manifest["config"], &manifest["layers"][0]] {
                    let blob = descriptor["digest"]
                        .as_str()
                        .context("missing blob digest")?;
                    ensure!(
                        state.blobs.contains_key(blob),
                        "artifact references a missing blob"
                    );
                }
                state.manifests.insert(address.to_owned(), body);
                let mut headers = vec![("Docker-Content-Digest", address)];
                if self.native_referrers {
                    headers.push(("OCI-Subject", &subject));
                }
                respond(&mut stream, "201 Created", &headers, &[])?;
            }
            _ => respond(&mut stream, "404 Not Found", &[], &[])?,
        }
        Ok(())
    }
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
