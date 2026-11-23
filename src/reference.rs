use std::{fmt, str::FromStr};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256, Sha512};

const DOCKER_HUB: &str = "registry-1.docker.io";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub selector: Selector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Selector {
    Tag(String),
    Digest(Digest),
}

impl Selector {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tag(tag) => tag,
            Self::Digest(digest) => digest.as_str(),
        }
    }
}

impl FromStr for ImageReference {
    type Err = anyhow::Error;

    fn from_str(reference: &str) -> Result<Self> {
        let (name, digest) = match reference.split_once('@') {
            Some((name, digest)) => (name, Some(digest.parse::<Digest>()?)),
            None => (reference, None),
        };

        let (registry, path) = match name.split_once('/') {
            Some((first, rest)) if is_registry_component(first) => {
                (normalize_registry(first)?, rest)
            }
            _ => (DOCKER_HUB.to_owned(), name),
        };

        let (path, tag) = path.rsplit_once(':').unwrap_or((path, "latest"));
        ensure!(valid_tag(tag), "invalid image tag {tag:?}");
        ensure!(
            path.split('/').all(valid_repository_component),
            "invalid image repository {path:?}"
        );
        let repository = if registry == DOCKER_HUB && !path.contains('/') {
            format!("library/{path}")
        } else {
            path.to_owned()
        };
        ensure!(repository.len() <= 255, "image repository is too long");

        let selector = match digest {
            Some(digest) => Selector::Digest(digest),
            None => Selector::Tag(tag.to_owned()),
        };
        Ok(Self {
            registry,
            repository,
            selector,
        })
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let separator = match self.selector {
            Selector::Tag(_) => ':',
            Selector::Digest(_) => '@',
        };
        write!(
            f,
            "{}/{}{separator}{}",
            self.registry,
            self.repository,
            self.selector.as_str()
        )
    }
}

fn is_registry_component(component: &str) -> bool {
    component.eq_ignore_ascii_case("localhost")
        || component.contains(['.', ':'])
        || component.starts_with('[')
        || component.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn normalize_registry(registry: &str) -> Result<String> {
    let (host, port) = if registry.starts_with('[') {
        let bracket = registry.find(']').context("unclosed IPv6 registry host")?;
        let (host, suffix) = registry.split_at(bracket + 1);
        let port = match suffix {
            "" => None,
            suffix => Some(suffix.strip_prefix(':').context("invalid registry port")?),
        };
        ensure!(
            host[1..bracket]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.')),
            "invalid IPv6 registry host"
        );
        (host, port)
    } else {
        let (host, port) = match registry.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (registry, None),
        };
        ensure!(
            host.len() <= 253 && host.split('.').all(valid_hostname_label),
            "invalid registry host {host:?}"
        );
        (host, port)
    };

    let url = reqwest::Url::parse(&format!("https://{host}/")).context("invalid registry host")?;
    let normalized_host = url.host_str().context("missing registry host")?;
    ensure!(
        host.starts_with('[') || host.eq_ignore_ascii_case(normalized_host),
        "use canonical dotted-decimal notation for IPv4 registry hosts"
    );

    if let Some(port) = port {
        ensure!(
            port.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid registry port {port:?}"
        );
        let port = port.parse::<u16>().context("invalid registry port")?;
        ensure!(port != 0, "invalid registry port 0");
        return Ok(format!("{normalized_host}:{port}"));
    }

    Ok(match normalized_host {
        "docker.io" | "index.docker.io" => DOCKER_HUB,
        host => host,
    }
    .to_owned())
}

fn valid_hostname_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn valid_tag(tag: &str) -> bool {
    let mut bytes = tag.bytes();
    tag.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_repository_component(component: &str) -> bool {
    let is_alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let mut bytes = component.bytes().peekable();
    loop {
        if bytes.next_if(is_alphanumeric).is_none() {
            return false;
        }
        while bytes.next_if(is_alphanumeric).is_some() {}

        match bytes.next() {
            None => return true,
            Some(b'.') => {}
            Some(b'_') => {
                bytes.next_if_eq(&b'_');
            }
            Some(b'-') => while bytes.next_if_eq(&b'-').is_some() {},
            _ => return false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Digest(String);

impl Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn sha256(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    pub fn sha512(bytes: &[u8]) -> Self {
        Self(format!("sha512:{}", hex::encode(Sha512::digest(bytes))))
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        let actual = if self.0.starts_with("sha256:") {
            Self::sha256(bytes)
        } else {
            Self::sha512(bytes)
        };
        ensure!(
            self == &actual,
            "digest mismatch (expected {self}, computed {actual})"
        );
        Ok(())
    }
}

impl FromStr for Digest {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (algorithm, encoded) = value
            .split_once(':')
            .context("digest must include an algorithm")?;
        let length = match algorithm {
            "sha256" => 64,
            "sha512" => 128,
            _ => bail!("unsupported digest algorithm {algorithm:?}"),
        };
        ensure!(
            encoded.len() == length
                && encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{algorithm} digest must contain {length} lowercase hexadecimal characters"
        );
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_tags_and_docker_hub_aliases() {
        for (input, expected) in [
            ("alpine", "registry-1.docker.io/library/alpine:latest"),
            (
                "docker.io/alpine",
                "registry-1.docker.io/library/alpine:latest",
            ),
            (
                "index.docker.io/tools/alpine:V2",
                "registry-1.docker.io/tools/alpine:V2",
            ),
            (
                "LOCALHOST:5000/tools/a__b--c:V2",
                "localhost:5000/tools/a__b--c:V2",
            ),
            ("[0:0:0:0:0:0:0:1]:5000/test", "[::1]:5000/test:latest"),
        ] {
            assert_eq!(
                input.parse::<ImageReference>().unwrap().to_string(),
                expected
            );
        }
    }

    #[test]
    fn selects_digest_over_tag() {
        let digest = Digest::sha512(b"manifest");
        let reference: ImageReference = format!("ghcr.io/tools/app:v2@{digest}").parse().unwrap();
        assert_eq!(reference.selector, Selector::Digest(digest.clone()));
        assert_eq!(reference.to_string(), format!("ghcr.io/tools/app@{digest}"));
    }

    #[test]
    fn rejects_invalid_image_references() {
        for input in [
            "https://registry.example.com/repo",
            "registry.example.com/repo?tag=foo",
            "registry.example.com/namespace/../repo",
            "registry.example.com/namespace/%2frepo",
            "registry.example.com:65536/repo",
            "registry.example.com:0/repo",
            "0177.0.0.1:5000/repo",
            "alpine:",
            "alpine:.bad",
            "alpine@sha256:1234",
            "user///alpine",
            "user/alpine__",
            "user/al___pine",
            "user/Alpine",
            "user/alpine\\escaped",
        ] {
            assert!(input.parse::<ImageReference>().is_err(), "accepted {input}");
        }
    }

    #[test]
    fn validates_digest_encoding_and_content() {
        let bytes = b"manifest";
        for digest in [Digest::sha256(bytes), Digest::sha512(bytes)] {
            assert_eq!(digest.as_str().parse::<Digest>().unwrap(), digest);
            digest.verify(bytes).unwrap();
            assert!(digest.verify(b"other bytes").is_err());
        }

        assert!(
            format!("sha256:{}", "A".repeat(64))
                .parse::<Digest>()
                .is_err()
        );
        assert!(
            format!("sha384:{}", "a".repeat(96))
                .parse::<Digest>()
                .is_err()
        );
    }
}
