use std::{
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::ValueEnum;
use getrandom::SysRng;
use ml_dsa::{Generate, MlDsa65, Seed, Signature, Signer, Verifier, VerifyingKey};
use pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
    PrivateKeyInfoRef, SecretDocument,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[cfg(windows)]
mod windows;

const MAX_KEY_FILE_SIZE: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
pub enum Algorithm {
    #[value(name = "ml-dsa-65")]
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[value(name = "ed25519")]
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[value(name = "ecdsa-p256")]
    #[serde(rename = "ECDSA-P256-SHA256")]
    EcdsaP256,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::Ed25519 => "Ed25519",
            Self::EcdsaP256 => "ECDSA-P256-SHA256",
        })
    }
}

pub enum SigningKey {
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    Ed25519(ed25519_dalek::SigningKey),
    EcdsaP256(p256::ecdsa::SigningKey),
}

impl SigningKey {
    pub fn load(path: &Path, algorithm: Algorithm) -> Result<Self> {
        let bytes = read_key_file(path)?;
        let pem = std::str::from_utf8(&bytes).context("private key PEM is not UTF-8")?;
        let result: Result<Self> = match algorithm {
            Algorithm::MlDsa65 => load_ml_dsa_private_key(pem).map(Self::MlDsa65),
            Algorithm::Ed25519 => ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
                .map(Self::Ed25519)
                .map_err(Into::into),
            Algorithm::EcdsaP256 => p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
                .map(Self::EcdsaP256)
                .map_err(Into::into),
        };
        result.with_context(|| format!("reading {algorithm} PKCS#8 key {}", path.display()))
    }

    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::MlDsa65(_) => Algorithm::MlDsa65,
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::EcdsaP256(_) => Algorithm::EcdsaP256,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::MlDsa65(key) => {
                let signature = key
                    .expanded_key()
                    .sign_randomized(message, b"", &mut SysRng)
                    .map_err(|_| anyhow!("could not create a randomized ML-DSA-65 signature"))?;
                Ok(signature.encode().to_vec())
            }
            Self::Ed25519(key) => {
                let signature: ed25519_dalek::Signature = key
                    .try_sign(message)
                    .context("could not create an Ed25519 signature")?;
                Ok(signature.to_bytes().to_vec())
            }
            Self::EcdsaP256(key) => {
                let signature: p256::ecdsa::Signature = key
                    .try_sign(message)
                    .context("could not create a P-256 ECDSA signature")?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    }

    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        match self {
            Self::MlDsa65(key) => Ok(key.as_ref().to_public_key_der()?.into_vec()),
            Self::Ed25519(key) => Ok(key.verifying_key().to_public_key_der()?.into_vec()),
            Self::EcdsaP256(key) => Ok(key.verifying_key().to_public_key_der()?.into_vec()),
        }
    }

    fn generate(algorithm: Algorithm) -> Result<Self> {
        let random_seed = || {
            let mut seed = Zeroizing::new(Seed::default());
            getrandom::fill(seed.as_mut_slice())?;
            Ok(seed)
        };

        let key: Result<Self, getrandom::Error> = match algorithm {
            Algorithm::MlDsa65 => {
                random_seed().map(|seed| Self::MlDsa65(ml_dsa::SigningKey::from_seed(&seed)))
            }
            Algorithm::Ed25519 => random_seed()
                .map(|seed| Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed.as_ref()))),
            Algorithm::EcdsaP256 => {
                p256::ecdsa::SigningKey::try_generate_from_rng(&mut SysRng).map(Self::EcdsaP256)
            }
        };
        key.with_context(|| format!("obtaining randomness for {algorithm} key"))
    }

    fn to_pem(&self) -> Result<(Zeroizing<String>, String)> {
        match self {
            Self::MlDsa65(key) => Ok((
                key.to_pkcs8_pem(LineEnding::LF)?,
                key.as_ref().to_public_key_pem(LineEnding::LF)?,
            )),
            Self::Ed25519(key) => {
                // PKCS#8 v1 omits the optional public key for compatibility with older readers.
                let mut keypair = ed25519::pkcs8::KeypairBytes::from(key);
                keypair.public_key = None;
                Ok((
                    keypair.to_pkcs8_pem(LineEnding::LF)?,
                    key.verifying_key().to_public_key_pem(LineEnding::LF)?,
                ))
            }
            Self::EcdsaP256(key) => Ok((
                key.to_pkcs8_pem(LineEnding::LF)?,
                key.verifying_key().to_public_key_pem(LineEnding::LF)?,
            )),
        }
    }
}

pub fn generate_keypair(
    private_key_path: &Path,
    public_key_path: &Path,
    algorithm: Algorithm,
) -> Result<()> {
    let private_key_path = new_file_path(private_key_path)?;
    let public_key_path = new_file_path(public_key_path)?;
    ensure!(
        private_key_path != public_key_path,
        "private and public keys require different output paths"
    );

    let (private_pem, public_pem) = SigningKey::generate(algorithm)?.to_pem()?;

    let private_file = stage_key_file(&private_key_path, private_pem.as_bytes(), private_tempfile)?;
    let public_file = stage_key_file(&public_key_path, public_pem.as_bytes(), |parent| {
        NamedTempFile::new_in(parent)
    })?;
    let public_file = public_file
        .persist_noclobber(&public_key_path)
        .map_err(|error| error.error)
        .with_context(|| format!("creating public key {}", public_key_path.display()))?;

    if let Err(error) = private_file.persist_noclobber(&private_key_path) {
        if let Err(cleanup) = remove_generated_public_key(&public_key_path, &public_file) {
            bail!(
                "could not create private key {} ({}). Cleanup of generated public key {} failed ({})",
                private_key_path.display(),
                error.error,
                public_key_path.display(),
                cleanup
            );
        }
        return Err(error.error)
            .with_context(|| format!("creating private key {}", private_key_path.display()));
    }
    Ok(())
}

pub enum PublicKey {
    MlDsa65(VerifyingKey<MlDsa65>),
    Ed25519(ed25519_dalek::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
}

impl PublicKey {
    pub fn load(path: &Path, algorithm: Algorithm) -> Result<Self> {
        let bytes = read_key_file(path)?;
        let pem = std::str::from_utf8(&bytes).context("public key PEM is not UTF-8")?;
        let result: Result<Self> = match algorithm {
            Algorithm::MlDsa65 => VerifyingKey::<MlDsa65>::from_public_key_pem(pem)
                .map(Self::MlDsa65)
                .map_err(Into::into),
            Algorithm::Ed25519 => ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
                .map(Self::Ed25519)
                .map_err(Into::into),
            Algorithm::EcdsaP256 => p256::ecdsa::VerifyingKey::from_public_key_pem(pem)
                .map(Self::EcdsaP256)
                .map_err(Into::into),
        };
        result.with_context(|| format!("reading {algorithm} public key {}", path.display()))
    }

    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::MlDsa65(_) => Algorithm::MlDsa65,
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::EcdsaP256(_) => Algorithm::EcdsaP256,
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let invalid_encoding = || anyhow!("invalid {} signature encoding", self.algorithm());
        let result = match self {
            Self::MlDsa65(key) => {
                let signature =
                    Signature::<MlDsa65>::try_from(signature).map_err(|_| invalid_encoding())?;
                key.verify(message, &signature).is_ok()
            }
            Self::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| invalid_encoding())?;
                key.verify_strict(message, &signature).is_ok()
            }
            Self::EcdsaP256(key) => {
                let signature =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| invalid_encoding())?;
                key.verify(message, &signature).is_ok()
            }
        };
        ensure!(result, "{} signature verification failed", self.algorithm());
        Ok(())
    }
}

fn load_ml_dsa_private_key(pem: &str) -> Result<ml_dsa::SigningKey<MlDsa65>> {
    let (label, document) = SecretDocument::from_pem(pem)?;
    ensure!(
        label == "PRIVATE KEY",
        "expected a PKCS#8 private key PEM label"
    );
    let key_info =
        PrivateKeyInfoRef::try_from(document.as_bytes()).context("invalid PKCS#8 private key")?;
    let embedded_public_key = key_info.public_key;
    let key = ml_dsa::SigningKey::<MlDsa65>::try_from(key_info)
        .context("invalid seed-form ML-DSA-65 private key")?;
    if let Some(public_key) = embedded_public_key {
        ensure!(
            public_key.as_bytes() == Some(key.as_ref().encode().as_slice()),
            "embedded public key differs from the key derived from the seed"
        );
    }
    Ok(key)
}

fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_SIZE + 1));
    File::open(path)
        .and_then(|file| {
            file.take((MAX_KEY_FILE_SIZE + 1) as u64)
                .read_to_end(&mut buffer)
        })
        .with_context(|| format!("reading key file {}", path.display()))?;
    ensure!(
        buffer.len() <= MAX_KEY_FILE_SIZE,
        "key file {} exceeds {MAX_KEY_FILE_SIZE} bytes",
        path.display()
    );
    Ok(buffer)
}

fn new_file_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("invalid key output path {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .with_context(|| format!("opening key output directory {}", parent.display()))?;
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => bail!("key output {} already exists", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error).with_context(|| format!("checking key output {}", path.display())),
    }
}

fn stage_key_file(
    path: &Path,
    bytes: &[u8],
    create: impl FnOnce(&Path) -> io::Result<NamedTempFile>,
) -> Result<NamedTempFile> {
    let parent = path
        .parent()
        .context("key output has no parent directory")?;
    let mut file =
        create(parent).with_context(|| format!("staging key file {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.as_file().sync_all())
        .with_context(|| format!("writing key file {}", path.display()))?;
    Ok(file)
}

#[cfg(windows)]
use windows::private_tempfile;

#[cfg(not(windows))]
fn private_tempfile(parent: &Path) -> io::Result<NamedTempFile> {
    // Named temporary files use mode 0600 on Unix.
    NamedTempFile::new_in(parent)
}

#[cfg(unix)]
fn remove_generated_public_key(path: &Path, file: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let generated = file.metadata()?;
    let current = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if current.dev() != generated.dev() || current.ino() != generated.ino() {
        return Err(io::Error::other(
            "public key path changed during key generation",
        ));
    }
    fs::remove_file(path)
}

#[cfg(not(unix))]
fn remove_generated_public_key(_path: &Path, _file: &File) -> io::Result<()> {
    Err(io::Error::other(
        "removing a generated key after concurrent changes is unsupported",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHMS: [Algorithm; 3] =
        [Algorithm::MlDsa65, Algorithm::Ed25519, Algorithm::EcdsaP256];

    #[test]
    fn imports_the_rfc_9881_ml_dsa_65_seed_key() -> Result<()> {
        // RFC 9881 C.1.2.1, with the SPKI fingerprint independently derived by OpenSSL.
        let pem = concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ\n",
            "GhscHR4f\n",
            "-----END PRIVATE KEY-----\n",
        );
        let key = SigningKey::MlDsa65(load_ml_dsa_private_key(pem)?);
        assert_eq!(
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                key.public_key_der()?
            )),
            "b8b62131bfbe84433efb2273d7f5b87f7a22854a2cfd366fc2aead86d837c52d",
        );
        Ok(())
    }

    #[test]
    fn generated_pem_round_trips_with_the_matching_key_and_algorithm() -> Result<()> {
        for algorithm in ALGORITHMS {
            let dir = tempfile::tempdir()?;
            let private = dir.path().join("private.pem");
            let public = dir.path().join("public.pem");
            let other_public = dir.path().join("other-public.pem");
            generate_keypair(&private, &public, algorithm)?;
            generate_keypair(
                &dir.path().join("other-private.pem"),
                &other_public,
                algorithm,
            )?;

            let key = SigningKey::load(&private, algorithm)?;
            let public_pem = fs::read_to_string(&public)?;
            let (label, public_der) = pkcs8::Document::from_pem(&public_pem)?;
            assert_eq!(label, "PUBLIC KEY");
            assert_eq!(public_der.as_bytes(), key.public_key_der()?);

            if algorithm == Algorithm::Ed25519 {
                let private_pem = Zeroizing::new(fs::read_to_string(&private)?);
                let (label, private_der) = SecretDocument::from_pem(&private_pem)?;
                assert_eq!(label, "PRIVATE KEY");
                let info = PrivateKeyInfoRef::try_from(private_der.as_bytes())?;
                assert!(
                    info.public_key.is_none(),
                    "Ed25519 export must use PKCS#8 v1"
                );
            }

            let message = b"DigestSeal key file test";
            let signature = key.sign(message)?;
            PublicKey::load(&public, algorithm)?.verify(message, &signature)?;
            let other_key = PublicKey::load(&other_public, algorithm)?;
            assert!(other_key.verify(message, &signature).is_err());

            assert!(SigningKey::load(&public, algorithm).is_err());
            assert!(PublicKey::load(&private, algorithm).is_err());
            for other in ALGORITHMS.into_iter().filter(|&other| other != algorithm) {
                assert!(SigningKey::load(&private, other).is_err());
                assert!(PublicKey::load(&public, other).is_err());
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                assert_eq!(fs::metadata(&private)?.permissions().mode() & 0o077, 0);
            }
        }
        Ok(())
    }

    #[test]
    fn key_generation_preserves_existing_output_and_leaves_no_partial_pair() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let private = dir.path().join("private.pem");
        let public = dir.path().join("public.pem");
        let existing_bytes = b"existing key file";

        for (existing, absent) in [(&private, &public), (&public, &private)] {
            fs::write(existing, existing_bytes)?;
            assert!(generate_keypair(&private, &public, Algorithm::Ed25519).is_err());
            assert_eq!(fs::read(existing)?, existing_bytes);
            assert!(!absent.exists());
            fs::remove_file(existing)?;
        }

        let alias = dir.path().join("./private.pem");
        assert!(generate_keypair(&private, &alias, Algorithm::Ed25519).is_err());
        assert!(!private.exists());
        Ok(())
    }
}
