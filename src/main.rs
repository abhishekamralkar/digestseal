mod bundle;
mod crypto;
mod reference;
mod registry;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use crate::crypto::Algorithm;
use crate::reference::ImageReference;
use crate::registry::Registry;

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
        #[command(flatten)]
        target: ImageTarget,
    },
    /// Attach an existing bundle to an image with the same digest.
    Reuse {
        #[arg(long, value_enum, default_value = "ml-dsa-65")]
        algorithm: Algorithm,
        #[arg(long, value_name = "FILE")]
        bundle: PathBuf,
        /// Trusted public key used to authenticate the bundle.
        #[arg(long, value_name = "FILE")]
        public_key: PathBuf,
        #[command(flatten)]
        target: ImageTarget,
    },
}

#[derive(Args)]
struct ImageTarget {
    /// OCI image reference, with a tag or a digest.
    #[arg(value_name = "IMAGE")]
    image: ImageReference,
    /// Connect to the registry over plain HTTP (for local testing).
    #[arg(long)]
    plain_http: bool,
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
            target,
        } => {
            bundle::ensure_new(&path)?;
            let key = crypto::SigningKey::load(&key, algorithm)?;
            let registry = Registry::new(&target.image, target.plain_http)?;
            let image = registry.resolve()?;
            let bundle = bundle::sign(&key, &image)?;
            bundle::save(&path, &bundle)?;
            println!("Saved signature bundle to {}", path.display());
            println!(
                "Signed {}/{}@{}",
                target.image.registry, target.image.repository, image.descriptor.digest
            );
            if !bundle_only {
                publish(&registry, &target.image, &image, &bundle).with_context(|| {
                    format!(
                        "Bundle saved at {}. Run reuse to retry publication with the same signature",
                        path.display()
                    )
                })?;
            }
        }
        Command::Reuse {
            algorithm,
            bundle: path,
            public_key,
            target,
        } => {
            let bytes = bundle::load(&path)?;
            let public_key = crypto::PublicKey::load(&public_key, algorithm)?;
            let signed_image = bundle::authenticate(&bytes, &public_key)
                .with_context(|| format!("Authenticating bundle {}", path.display()))?;
            let registry = Registry::new(&target.image, target.plain_http)?;
            let image = registry.resolve()?;
            signed_image.matches(&image)?;
            publish(&registry, &target.image, &image, &bytes)?;
        }
    }
    Ok(())
}

fn publish(
    registry: &Registry,
    reference: &ImageReference,
    image: &registry::ResolvedImage,
    bundle: &[u8],
) -> Result<()> {
    let signature = registry.publish(&image.descriptor, bundle::ARTIFACT_TYPE, bundle)?;
    println!(
        "Published signature {}/{}@{}",
        reference.registry, reference.repository, signature.digest
    );
    Ok(())
}
