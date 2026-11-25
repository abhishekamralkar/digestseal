use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::crypto::{Algorithm, PublicKey, SigningKey};
use crate::reference::{Descriptor, Digest};
use crate::registry::ResolvedImage;

// Preserve the media types used by existing signature artifacts and signed payloads.
pub const ARTIFACT_TYPE: &str = "application/vnd.microsign.signature.v1+json";
const PAYLOAD_TYPE: &str = "application/vnd.microsign.image-signature.payload.v1+json";
const MAX_BUNDLE_SIZE: u64 = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    payload_type: String,
    payload: String,
    signatures: [Signature; 1],
}

#[derive(Serialize, Deserialize)]
struct Signature {
    #[serde(skip_serializing_if = "Option::is_none")]
    keyid: Option<String>,
    sig: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImagePayload {
    algorithm: Algorithm,
    subject: Descriptor,
    manifest_sha512: Digest,
}

impl ImagePayload {
    pub fn matches(&self, image: &ResolvedImage) -> Result<()> {
        ensure!(
            self.subject.digest == image.descriptor.digest,
            "Bundle signs {}, but the target resolves to {}",
            self.subject.digest,
            image.descriptor.digest
        );
        ensure!(
            self.subject.media_type == image.descriptor.media_type
                && self.subject.size == image.descriptor.size
                && self.manifest_sha512 == image.manifest_sha512,
            "Target manifest differs from the signed manifest"
        );
        Ok(())
    }
}

pub fn sign(key: &SigningKey, image: &ResolvedImage) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(&ImagePayload {
        algorithm: key.algorithm(),
        subject: image.descriptor.clone(),
        manifest_sha512: image.manifest_sha512.clone(),
    })?;
    let signature = key.sign(&pae(PAYLOAD_TYPE, &payload))?;
    let envelope = Envelope {
        payload_type: PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: [Signature {
            keyid: Some(Digest::sha256(&key.public_key_der()?).to_string()),
            sig: STANDARD.encode(signature),
        }],
    };
    let mut bytes = serde_json::to_vec(&envelope)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn authenticate(bundle: &[u8], public_key: &PublicKey) -> Result<ImagePayload> {
    let envelope: Envelope = serde_json::from_slice(bundle).context("Invalid DSSE envelope")?;
    ensure!(
        envelope.payload_type == PAYLOAD_TYPE,
        "Unsupported payload type {:?}",
        envelope.payload_type
    );
    let payload = decode_base64(&envelope.payload).context("Invalid DSSE payload")?;
    let signature = decode_base64(&envelope.signatures[0].sig).context("Invalid DSSE signature")?;
    public_key.verify(&pae(&envelope.payload_type, &payload), &signature)?;
    let metadata: ImagePayload =
        serde_json::from_slice(&payload).context("Invalid signed image metadata")?;
    ensure!(
        metadata.algorithm == public_key.algorithm(),
        "Bundle declares {}, but the selected algorithm is {}",
        metadata.algorithm,
        public_key.algorithm()
    );
    Ok(metadata)
}

fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    message.extend_from_slice(payload);
    message
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .context("Expected base64-encoded bytes")
}

pub fn ensure_new(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "Bundle {} already exists. Run reuse to publish it",
            path.display()
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Checking bundle {}", path.display())),
    }
}

pub fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    let parent = File::open(directory)
        .with_context(|| format!("Opening bundle directory {}", directory.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(directory)
        .with_context(|| format!("Creating temporary bundle in {}", directory.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.as_file().sync_all())
        .with_context(|| format!("Writing bundle {}", path.display()))?;
    file.persist_noclobber(path)
        .with_context(|| format!("Saving bundle {}", path.display()))?;
    // The file sync does not make the new directory entry durable.
    #[cfg(unix)]
    parent.sync_all().with_context(|| {
        format!(
            "Bundle {} was saved but its directory could not be synchronized",
            path.display()
        )
    })?;
    Ok(())
}

pub fn load(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("Opening bundle {}", path.display()))?
        .take(MAX_BUNDLE_SIZE + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Reading bundle {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_BUNDLE_SIZE,
        "Bundle exceeds the {MAX_BUNDLE_SIZE}-byte limit"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn verifies_bundle_signed_by_openssl() -> Result<()> {
        // OpenSSL signed this exact payload using independently assembled DSSE PAE.
        let payload = concat!(
            r#"{"algorithm":"Ed25519","subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","#,
            r#""digest":"sha256:6ae2621842b9924bc60f532c86de098318bad18bef01c826eee55433c8b12955","size":20},"#,
            r#""manifestSha512":"sha512:bc01447a9f9ee5397ce4cfcdb1f92e2300b8e7ceb8d7f8b79ff7a8d72dd3731fa2"#,
            r#"ab24e600e590f42a1100fed7b6f563c860e7b8f5b7d9b2193b5ac6e2b5f94e"}"#,
        );
        let envelope = serde_json::json!({
            "payloadType": "application/vnd.microsign.image-signature.payload.v1+json",
            "payload": STANDARD.encode(payload),
            "signatures": [{
                "sig": "t1N96ExukAR3yHt9Hbeco4+C+gQ0rDTqjOe5YBoIXQZBkVls61O4FbjBgc8jPaRHtW2U3h4oTfgzPRyDt0MRDg==",
            }],
        });
        let dir = tempfile::tempdir()?;
        let public_path = dir.path().join("pub.pem");
        fs::write(
            &public_path,
            concat!(
                "-----BEGIN PUBLIC KEY-----\n",
                "MCowBQYDK2VwAyEAFR7xRHFi3/ExuE/eC/4OQL6jQ4PXYQTxVvgotRqO+Mo=\n",
                "-----END PUBLIC KEY-----\n",
            ),
        )?;
        let key = PublicKey::load(&public_path, Algorithm::Ed25519)?;
        let metadata = authenticate(&serde_json::to_vec(&envelope)?, &key)?;
        assert_eq!(metadata.algorithm, Algorithm::Ed25519);
        assert_eq!(
            metadata.subject.digest,
            Digest::sha256(b"example OCI manifest")
        );
        assert_eq!(
            metadata.manifest_sha512,
            Digest::sha512(b"example OCI manifest")
        );
        Ok(())
    }

    #[test]
    fn reuse_checks_the_signed_manifest_and_algorithm() -> Result<()> {
        for (algorithm, other_algorithm) in [
            (Algorithm::MlDsa65, Algorithm::Ed25519),
            (Algorithm::Ed25519, Algorithm::EcdsaP256),
            (Algorithm::EcdsaP256, Algorithm::MlDsa65),
        ] {
            check_reuse(algorithm, other_algorithm)?;
        }
        Ok(())
    }

    fn check_reuse(algorithm: Algorithm, other_algorithm: Algorithm) -> Result<()> {
        let dir = tempfile::tempdir()?;
        let private_path = dir.path().join("key.pem");
        let public_path = dir.path().join("pub.pem");
        crypto::generate_keypair(&private_path, &public_path, algorithm)?;
        let key = SigningKey::load(&private_path, algorithm)?;
        let public_key = PublicKey::load(&public_path, algorithm)?;
        let raw_manifest = b"example manifest bytes";
        let mut image = ResolvedImage {
            descriptor: Descriptor {
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                digest: Digest::sha256(raw_manifest),
                size: raw_manifest.len() as u64,
            },
            manifest_sha512: Digest::sha512(raw_manifest),
        };

        let bundle = sign(&key, &image)?;
        let mut authenticated = authenticate(&bundle, &public_key)?;
        assert_eq!(authenticated.algorithm, algorithm);
        authenticated.matches(&image)?;

        image.manifest_sha512 = Digest::sha512(b"different manifest");
        assert!(authenticated.matches(&image).is_err());

        let mut envelope: Envelope = serde_json::from_slice(&bundle)?;
        authenticated.algorithm = other_algorithm;
        let changed_payload = serde_json::to_vec(&authenticated)?;
        envelope.payload = STANDARD.encode(&changed_payload);
        assert!(authenticate(&serde_json::to_vec(&envelope)?, &public_key).is_err());

        // Reject the wrong declared algorithm even when the signature is valid.
        envelope.signatures[0].sig =
            STANDARD.encode(key.sign(&pae(PAYLOAD_TYPE, &changed_payload))?);
        assert!(authenticate(&serde_json::to_vec(&envelope)?, &public_key).is_err());
        Ok(())
    }
}
