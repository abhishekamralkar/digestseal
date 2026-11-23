use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
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

    assert_success(
        digestseal("keygen", option)
            .arg("--private-key")
            .arg(&private_key)
            .arg("--public-key")
            .arg(&public_key)
            .output()?,
    );
    assert_success(
        digestseal("sign", option)
            .arg("--key")
            .arg(&private_key)
            .arg("--bundle")
            .arg(&bundle)
            .arg("--plain-http")
            .arg(registry.image(SOURCE))
            .output()?,
    );
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

    let reuse = |repository| {
        digestseal("reuse", option)
            .arg("--bundle")
            .arg(&bundle)
            .arg("--public-key")
            .arg(&public_key)
            .arg("--plain-http")
            .arg(registry.image(repository))
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
    let output = reuse(CHANGED)?;
    assert!(!output.status.success());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostic.contains("but the target resolves to"),
        "{diagnostic}"
    );
    assert_eq!(registry.state.lock().unwrap().write_requests, writes);
    Ok(())
}

fn digestseal(operation: &str, algorithm: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_digestseal"));
    command
        .arg(operation)
        .env_remove("DIGESTSEAL_REGISTRY_USERNAME")
        .env_remove("DIGESTSEAL_REGISTRY_PASSWORD")
        .env_remove("DIGESTSEAL_REGISTRY_AUTH_HOST")
        .env_remove("MICROSIGN_REGISTRY_USERNAME")
        .env_remove("MICROSIGN_REGISTRY_PASSWORD")
        .env_remove("MICROSIGN_REGISTRY_AUTH_HOST")
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

struct TestRegistry {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    server: Option<JoinHandle<()>>,
}

struct State {
    repositories: HashMap<&'static str, Repository>,
    write_requests: usize,
}

struct Repository {
    image: Vec<u8>,
    blobs: HashMap<String, Vec<u8>>,
    manifests: HashMap<String, Vec<u8>>,
}

impl TestRegistry {
    fn start() -> Result<Self> {
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
        }
    }
}

impl State {
    fn handle(&mut self, mut stream: BufReader<TcpStream>, request_line: &str) -> Result<()> {
        let mut parts = request_line.split_whitespace();
        let method = parts.next().context("missing method")?;
        let target = parts.next().context("missing target")?;
        let mut length = 0;
        loop {
            let mut line = String::new();
            ensure!(
                stream.read_line(&mut line)? > 0,
                "incomplete request headers"
            );
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse()?;
            }
        }
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
                respond(
                    &mut stream,
                    "201 Created",
                    &[
                        ("Docker-Content-Digest", address),
                        ("OCI-Subject", &subject),
                    ],
                    &[],
                )?;
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
