mod bundle;
mod crypto;
mod reference;
mod registry;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};

use crate::crypto::Algorithm;
use crate::reference::{ImageReference, Selector};
use crate::registry::{Registry, ResolvedImage};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a signing key pair as PEM files.
    Keygen {
        #[arg(long, value_enum, default_value = "ml-dsa-65")]
        algorithm: Algorithm,
        #[arg(long, value_name = "FILE")]
        private_key: PathBuf,
        #[arg(long, value_name = "FILE")]
        public_key: PathBuf,
    },
    /// Sign an image and save the signature as a detached bundle.
    Sign {
        #[arg(long, value_enum, default_value = "ml-dsa-65")]
        algorithm: Algorithm,
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, value_name = "FILE")]
        bundle: PathBuf,
        /// Save the bundle without attaching it to the registry image.
        #[arg(long)]
        bundle_only: bool,
        /// Require an image reference pinned to a digest.
        #[arg(long)]
        require_digest: bool,
        /// Require the native OCI referrers API for publication.
        #[arg(long, conflicts_with = "bundle_only")]
        native_referrers_only: bool,
        #[command(flatten)]
        target: ImageTarget,
    },
    /// Attach an existing bundle to an image with the same digest.
    Reuse {
        /// Require the native OCI referrers API for publication.
        #[arg(long)]
        native_referrers_only: bool,
        #[command(flatten)]
        input: BundleTarget,
    },
    /// Verify a detached bundle against a digest-pinned image with pull access.
    Verify(BundleTarget),
}

#[derive(Args)]
struct BundleTarget {
    #[arg(long, value_enum, default_value = "ml-dsa-65")]
    algorithm: Algorithm,
    #[arg(long, value_name = "FILE")]
    bundle: PathBuf,
    /// Trusted public key used to authenticate the bundle.
    #[arg(long, value_name = "FILE")]
    public_key: PathBuf,
    #[command(flatten)]
    target: ImageTarget,
}

impl BundleTarget {
    fn authenticate(&self) -> Result<(Vec<u8>, bundle::ImagePayload)> {
        let bytes = bundle::load(&self.bundle)?;
        let key = crypto::PublicKey::load(&self.public_key, self.algorithm)?;
        let payload = bundle::authenticate(&bytes, &key)
            .with_context(|| format!("Authenticating bundle {}", self.bundle.display()))?;
        Ok((bytes, payload))
    }
}

#[derive(Args)]
struct ImageTarget {
    /// OCI image reference, with a tag or a digest.
    #[arg(value_name = "IMAGE")]
    image: ImageReference,
    /// Use unauthenticated HTTP for a loopback test registry.
    #[arg(long)]
    plain_http: bool,
}

impl ImageTarget {
    fn require_digest(&self) -> Result<()> {
        ensure!(
            matches!(self.image.selector, Selector::Digest(_)),
            "use a digest-pinned image reference (IMAGE@DIGEST)"
        );
        Ok(())
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Keygen {
            algorithm,
            private_key,
            public_key,
        } => {
            crypto::generate_keypair(&private_key, &public_key, algorithm)?;
            println!("Wrote {algorithm} key pair");
        }
        Command::Sign {
            algorithm,
            key,
            bundle: path,
            bundle_only,
            require_digest,
            native_referrers_only,
            target,
        } => {
            if require_digest {
                target.require_digest()?;
            }
            bundle::ensure_new(&path)?;
            let registry = Registry::new(&target.image, target.plain_http)?;
            let image = registry.resolve()?;
            let bundle = {
                let key = crypto::SigningKey::load(&key, algorithm)?;
                bundle::sign(&key, &image)?
            };
            bundle::save(&path, &bundle)?;
            println!("Saved signature bundle to {}", path.display());
            println!(
                "Signed {}/{}@{}",
                target.image.registry, target.image.repository, image.descriptor.digest
            );
            if !bundle_only {
                publish(
                    &registry,
                    &target.image,
                    &image,
                    &bundle,
                    native_referrers_only,
                )
                .with_context(|| {
                    format!(
                        "Bundle saved at {}. Run reuse with the same publication options to retry",
                        path.display()
                    )
                })?;
            }
        }
        Command::Reuse {
            native_referrers_only,
            input,
        } => {
            let (bytes, signed_image) = input.authenticate()?;
            let target = &input.target;
            let registry = Registry::new(&target.image, target.plain_http)?;
            let image = registry.resolve()?;
            signed_image.matches(&image)?;
            publish(
                &registry,
                &target.image,
                &image,
                &bytes,
                native_referrers_only,
            )?;
        }
        Command::Verify(input) => {
            let target = &input.target;
            target.require_digest()?;
            let (_, signed_image) = input.authenticate()?;
            let registry = Registry::new(&target.image, target.plain_http)?;
            signed_image.matches(&registry.resolve()?)?;
            println!("Verified {}", target.image);
        }
    }
    Ok(())
}

fn publish(
    registry: &Registry,
    reference: &ImageReference,
    image: &ResolvedImage,
    bundle: &[u8],
    native_referrers_only: bool,
) -> Result<()> {
    let signature = registry.publish(
        &image.descriptor,
        bundle::ARTIFACT_TYPE,
        bundle,
        native_referrers_only,
    )?;
    println!(
        "Published signature {}/{}@{}",
        reference.registry, reference.repository, signature.digest
    );
    Ok(())
}
