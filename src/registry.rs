use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_auth::{ChallengeParser, ChallengeRef};
use reqwest::blocking::{Client, Request, Response};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderMap, HeaderValue, IF_MATCH,
    IF_NONE_MATCH, LOCATION, WWW_AUTHENTICATE,
};
use reqwest::{Method, StatusCode, Url, redirect};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::reference::{Descriptor, Digest, ImageReference, Selector};

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const EMPTY_CONFIG: &str = "application/vnd.oci.empty.v1+json";
const IMAGE_MEDIA_TYPES: [&str; 4] = [OCI_MANIFEST, OCI_INDEX, DOCKER_MANIFEST, DOCKER_INDEX];
const CONTENT_DIGEST: &str = "docker-content-digest";
const OCI_SUBJECT: &str = "oci-subject";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_FALLBACK_ATTEMPTS: usize = 4;
const REGISTRY_ENV: [&str; 3] = [
    "DIGESTSEAL_REGISTRY_USERNAME",
    "DIGESTSEAL_REGISTRY_PASSWORD",
    "DIGESTSEAL_REGISTRY_AUTH_HOST",
];
const LEGACY_REGISTRY_ENV: [&str; 3] = [
    "MICROSIGN_REGISTRY_USERNAME",
    "MICROSIGN_REGISTRY_PASSWORD",
    "MICROSIGN_REGISTRY_AUTH_HOST",
];

pub struct ResolvedImage {
    pub descriptor: Descriptor,
    pub manifest_sha512: Digest,
}

pub struct Registry {
    client: Client,
    base: Url,
    image: ImageReference,
    credentials: Option<Credentials>,
    auth_origin: Option<Url>,
    pull_auth: RefCell<Option<HeaderValue>>,
    push_auth: RefCell<Option<HeaderValue>>,
}

struct Credentials {
    username: String,
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestMetadata {
    schema_version: u32,
    media_type: Option<String>,
    config: Option<BTreeMap<String, IgnoredAny>>,
    layers: Option<Vec<IgnoredAny>>,
    manifests: Option<Vec<IgnoredAny>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactManifest<'a> {
    schema_version: u32,
    media_type: &'a str,
    artifact_type: &'a str,
    config: Descriptor,
    layers: [Descriptor; 1],
    subject: &'a Descriptor,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReferrersIndex {
    schema_version: u32,
    media_type: Option<String>,
    manifests: Vec<Value>,
    #[serde(flatten)]
    fields: BTreeMap<String, Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Referrer<'a> {
    #[serde(flatten)]
    descriptor: &'a Descriptor,
    artifact_type: &'a str,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

impl Registry {
    pub fn new(image: &ImageReference, insecure_http: bool) -> Result<Self> {
        let scheme = if insecure_http { "http" } else { "https" };
        let base = Url::parse(&format!("{scheme}://{}/", image.registry))
            .context("invalid registry host")?;
        let (credentials, auth_origin) = registry_environment(|name| env::var_os(name))?;

        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(redirect::Policy::custom(registry_redirect))
            .referer(false)
            .build()
            .context("could not initialize HTTP client")?;

        Ok(Self {
            client,
            base,
            image: image.clone(),
            credentials,
            auth_origin,
            pull_auth: RefCell::new(None),
            push_auth: RefCell::new(None),
        })
    }

    pub fn resolve(&self) -> Result<ResolvedImage> {
        let url = self.endpoint(&format!("manifests/{}", self.image.selector.as_str()))?;
        let request = self
            .client
            .get(url)
            .header(ACCEPT, IMAGE_MEDIA_TYPES.join(", "))
            .build()?;
        let response = self.send(request)?;
        expect_status(&response, StatusCode::OK, "resolve image manifest")?;
        let media_type = content_type(&response)?.to_owned();
        ensure!(
            IMAGE_MEDIA_TYPES.contains(&media_type.as_str()),
            "registry returned an unsupported image manifest media type"
        );
        let reported_digest = reported_digest(&response)?;
        let raw = read_body(response, MAX_MANIFEST_BYTES, "image manifest")?;
        let metadata: ManifestMetadata =
            serde_json::from_slice(&raw).context("invalid image manifest JSON")?;
        ensure!(
            metadata.schema_version == 2,
            "unsupported manifest schema version"
        );
        if let Some(body_media_type) = metadata.media_type {
            ensure!(
                body_media_type == media_type,
                "image manifest media type differs from its HTTP content type"
            );
        }
        if matches!(media_type.as_str(), OCI_INDEX | DOCKER_INDEX) {
            ensure!(
                metadata.manifests.is_some(),
                "image index omits its manifests array"
            );
        } else {
            ensure!(
                metadata.config.is_some() && metadata.layers.is_some(),
                "image manifest omits its config object or layers array"
            );
        }
        if let Some(digest) = &reported_digest {
            digest
                .verify(&raw)
                .context("registry reported an invalid image digest")?;
        }
        let digest = match &self.image.selector {
            Selector::Digest(digest) => {
                digest
                    .verify(&raw)
                    .context("registry returned a different image manifest")?;
                digest.clone()
            }
            Selector::Tag(_) => reported_digest.unwrap_or_else(|| Digest::sha256(&raw)),
        };
        Ok(ResolvedImage {
            descriptor: Descriptor {
                media_type,
                digest,
                size: raw.len() as u64,
            },
            manifest_sha512: Digest::sha512(&raw),
        })
    }

    pub fn publish(
        &self,
        subject: &Descriptor,
        artifact_type: &str,
        blob: &[u8],
    ) -> Result<Descriptor> {
        let config = describe(EMPTY_CONFIG, b"{}");
        let signature = describe(artifact_type, blob);
        self.upload_blob(&config, b"{}")?;
        self.upload_blob(&signature, blob)?;

        let raw = serde_json::to_vec(&ArtifactManifest {
            schema_version: 2,
            media_type: OCI_MANIFEST,
            artifact_type,
            config,
            layers: [signature],
            subject,
        })?;
        let artifact = describe(OCI_MANIFEST, &raw);
        let request = self.manifest_put(artifact.digest.as_str(), OCI_MANIFEST, raw.clone())?;
        let response = self.send(request)?;
        expect_status(&response, StatusCode::CREATED, "publish signature artifact")?;
        verify_reported_digest(&response, &raw)?;

        match response.headers().get(OCI_SUBJECT) {
            Some(value) => ensure!(
                value.to_str()? == subject.digest.as_str(),
                "registry acknowledged a different signature subject"
            ),
            None => self.update_referrers_tag(&subject.digest, &artifact, artifact_type)?,
        }
        Ok(artifact)
    }

    fn endpoint(&self, suffix: &str) -> Result<Url> {
        self.base
            .join(&format!("v2/{}/{suffix}", self.image.repository))
            .context("could not construct registry endpoint")
    }

    fn upload_blob(&self, descriptor: &Descriptor, bytes: &[u8]) -> Result<()> {
        let url = self.endpoint(&format!("blobs/{}", descriptor.digest))?;
        let response = self.send(self.client.head(url).build()?)?;
        if response.status() == StatusCode::OK {
            return verify_reported_digest(&response, bytes);
        }
        expect_status(&response, StatusCode::NOT_FOUND, "check signature blob")?;

        let start = self.endpoint("blobs/uploads/")?;
        let request = self
            .client
            .post(start)
            .header(CONTENT_LENGTH, "0")
            .build()?;
        let response = self.send(request)?;
        expect_status(
            &response,
            StatusCode::ACCEPTED,
            "start signature blob upload",
        )?;
        let location = response
            .headers()
            .get(LOCATION)
            .context("registry omitted the blob upload location")?
            .to_str()?;
        let mut target = response
            .url()
            .join(location)
            .context("invalid blob upload location")?;
        ensure!(
            valid_target(&self.base, &target),
            "registry returned an unsafe blob upload location"
        );
        ensure!(
            !target.query_pairs().any(|(key, _)| key == "digest"),
            "blob upload location already contains a digest"
        );
        target
            .query_pairs_mut()
            .append_pair("digest", descriptor.digest.as_str());
        let request = self
            .client
            .put(target)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec())
            .build()?;
        let response = self.send(request)?;
        expect_status(
            &response,
            StatusCode::CREATED,
            "finish signature blob upload",
        )?;
        verify_reported_digest(&response, bytes)
    }

    fn manifest_put(&self, reference: &str, media_type: &str, raw: Vec<u8>) -> Result<Request> {
        let url = self.endpoint(&format!("manifests/{reference}"))?;
        Ok(self
            .client
            .put(url)
            .header(CONTENT_TYPE, media_type)
            .body(raw)
            .build()?)
    }

    fn update_referrers_tag(
        &self,
        subject: &Digest,
        artifact: &Descriptor,
        artifact_type: &str,
    ) -> Result<()> {
        let (algorithm, encoded) = subject
            .as_str()
            .split_once(':')
            .context("invalid subject digest")?;
        let tag = format!("{algorithm}-{}", &encoded[..encoded.len().min(64)]);
        let url = self.endpoint(&format!("manifests/{tag}"))?;
        for _ in 0..MAX_FALLBACK_ATTEMPTS {
            let response = self.send(
                self.client
                    .get(url.clone())
                    .header(ACCEPT, OCI_INDEX)
                    .build()?,
            )?;
            let (mut index, condition) = if response.status() == StatusCode::NOT_FOUND {
                let index = ReferrersIndex {
                    schema_version: 2,
                    media_type: Some(OCI_INDEX.to_owned()),
                    manifests: Vec::new(),
                    fields: BTreeMap::new(),
                };
                (index, Some((IF_NONE_MATCH, HeaderValue::from_static("*"))))
            } else {
                expect_status(&response, StatusCode::OK, "read referrers tag")?;
                ensure!(
                    content_type(&response)? == OCI_INDEX,
                    "referrers tag does not point to an OCI image index"
                );
                let condition = response
                    .headers()
                    .get(ETAG)
                    .filter(|value| value.as_bytes().starts_with(b"\""))
                    .map(|value| (IF_MATCH, value.clone()));
                let digest = reported_digest(&response)?;
                let raw = read_body(response, MAX_MANIFEST_BYTES, "referrers index")?;
                if let Some(digest) = digest {
                    digest
                        .verify(&raw)
                        .context("registry reported an invalid referrers index digest")?;
                }
                let index: ReferrersIndex =
                    serde_json::from_slice(&raw).context("invalid referrers index JSON")?;
                ensure!(
                    index.schema_version == 2
                        && index
                            .media_type
                            .as_deref()
                            .is_none_or(|mime| mime == OCI_INDEX),
                    "referrers tag does not point to an OCI image index"
                );
                (index, condition)
            };
            if index.manifests.iter().any(|entry| {
                entry.get("digest").and_then(Value::as_str) == Some(artifact.digest.as_str())
            }) {
                return Ok(());
            }
            index.manifests.push(serde_json::to_value(Referrer {
                descriptor: artifact,
                artifact_type,
            })?);
            index.media_type = Some(OCI_INDEX.to_owned());
            let raw = serde_json::to_vec(&index)?;
            let mut request = self.manifest_put(&tag, OCI_INDEX, raw.clone())?;
            if let Some((header, value)) = condition {
                request.headers_mut().insert(header, value);
            }
            let response = self.send(request)?;
            if matches!(
                response.status(),
                StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED
            ) {
                continue;
            }
            expect_status(&response, StatusCode::CREATED, "update referrers tag")?;
            return verify_reported_digest(&response, &raw);
        }
        bail!("referrers tag changed during publication, retry the signature attachment")
    }

    fn send(&self, mut request: Request) -> Result<Response> {
        if request.url().origin() != self.base.origin() {
            return self.execute(request);
        }
        let cache = if matches!(*request.method(), Method::GET | Method::HEAD) {
            &self.pull_auth
        } else {
            &self.push_auth
        };
        let mut retry = request
            .try_clone()
            .context("could not copy registry request")?;
        if let Some(header) = cache.borrow().as_ref() {
            request.headers_mut().insert(AUTHORIZATION, header.clone());
        }
        let response = self.execute(request)?;
        if response.status() != StatusCode::UNAUTHORIZED
            || response.url().origin() != self.base.origin()
        {
            return Ok(response);
        }

        let auth = self.authenticate(response.headers())?;
        drop(response);
        retry.headers_mut().insert(AUTHORIZATION, auth.clone());
        let response = self.execute(retry)?;
        if !matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            cache.replace(Some(auth));
        }
        Ok(response)
    }

    fn authenticate(&self, headers: &HeaderMap) -> Result<HeaderValue> {
        let mut basic = false;
        for value in headers.get_all(WWW_AUTHENTICATE) {
            for challenge in ChallengeParser::new(value.to_str()?).flatten() {
                if challenge.scheme.eq_ignore_ascii_case("bearer") {
                    return self.bearer_auth(&challenge);
                }
                basic |= challenge.scheme.eq_ignore_ascii_case("basic");
            }
        }
        if basic {
            return self
                .credentials
                .as_ref()
                .context(
                    "registry requires DIGESTSEAL_REGISTRY_USERNAME and DIGESTSEAL_REGISTRY_PASSWORD",
                )?
                .authorization();
        }
        bail!("registry did not provide a supported authentication challenge")
    }

    fn bearer_auth(&self, challenge: &ChallengeRef<'_>) -> Result<HeaderValue> {
        let realm = challenge_param(challenge, "realm")
            .context("registry auth challenge omitted its realm")?;
        let mut target = Url::parse(&realm).context("invalid registry authentication realm")?;
        ensure!(
            valid_target(&self.base, &target),
            "registry provided an unsafe authentication realm"
        );
        if let Some(service) = challenge_param(challenge, "service") {
            target.query_pairs_mut().append_pair("service", &service);
        }
        if let Some(scope) = challenge_param(challenge, "scope") {
            for scope in scope.split_ascii_whitespace() {
                target.query_pairs_mut().append_pair("scope", scope);
            }
        }
        let mut request = self.client.get(target).build()?;
        if let Some(credentials) = &self.credentials {
            ensure!(
                self.accepts_credentials(request.url()),
                "registry authentication realm is outside the credential allow-list; if you trust it, configure DIGESTSEAL_REGISTRY_AUTH_HOST alongside the DIGESTSEAL_REGISTRY credentials"
            );
            request
                .headers_mut()
                .insert(AUTHORIZATION, credentials.authorization()?);
        }
        let response = self.execute(request)?;
        expect_status(&response, StatusCode::OK, "obtain registry access token")?;
        let raw = Zeroizing::new(read_body(
            response,
            MAX_TOKEN_BYTES,
            "registry access token",
        )?);
        let token: TokenResponse =
            serde_json::from_slice(&raw).context("invalid registry token response")?;
        let token = Zeroizing::new(
            token
                .token
                .filter(|token| !token.is_empty())
                .or(token.access_token.filter(|token| !token.is_empty()))
                .context("registry token response contained no access token")?,
        );
        authorization("Bearer", &token)
    }

    fn accepts_credentials(&self, target: &Url) -> bool {
        if target.origin() == self.base.origin() {
            return true;
        }
        if target.scheme() != "https" {
            return false;
        }
        let docker_hub = self.base.scheme() == "https"
            && self.base.host_str() == Some("registry-1.docker.io")
            && self.base.port().is_none()
            && target.host_str() == Some("auth.docker.io")
            && target.port().is_none();
        docker_hub
            || self
                .auth_origin
                .as_ref()
                .is_some_and(|url| url.origin() == target.origin())
    }

    fn execute(&self, request: Request) -> Result<Response> {
        self.client
            .execute(request)
            .map_err(reqwest::Error::without_url)
            .context("registry request failed")
    }
}

impl Credentials {
    fn authorization(&self) -> Result<HeaderValue> {
        let plain = Zeroizing::new(format!("{}:{}", self.username, self.password.as_str()));
        let encoded = Zeroizing::new(STANDARD.encode(plain.as_bytes()));
        authorization("Basic", &encoded)
    }
}

fn authorization(scheme: &str, secret: &str) -> Result<HeaderValue> {
    let raw = Zeroizing::new(format!("{scheme} {secret}"));
    let mut value = HeaderValue::from_str(&raw).context("invalid registry authorization value")?;
    value.set_sensitive(true);
    Ok(value)
}

fn parse_auth_origin(host: &str) -> Result<Url> {
    ensure!(
        !host.is_empty()
            && !host.chars().any(|character| {
                character.is_whitespace() || matches!(character, '/' | '\\' | '%' | '@' | '?' | '#')
            }),
        "DIGESTSEAL_REGISTRY_AUTH_HOST must be a hostname with optional port"
    );
    Url::parse(&format!("https://{host}/")).context("invalid DIGESTSEAL_REGISTRY_AUTH_HOST")
}

fn registry_environment(
    read: impl Fn(&str) -> Option<OsString>,
) -> Result<(Option<Credentials>, Option<Url>)> {
    let current = REGISTRY_ENV.map(&read);
    let [username, password, auth_host] = if current.iter().all(Option::is_none) {
        LEGACY_REGISTRY_ENV.map(read)
    } else {
        current
    };
    let [username_name, password_name, host_name] = REGISTRY_ENV;
    let credentials = match (
        decode_env(username_name, username)?,
        decode_env(password_name, password)?.map(Zeroizing::new),
    ) {
        (Some(username), Some(password)) => {
            ensure!(
                !username.is_empty() && !username.contains(':') && !password.is_empty(),
                "registry credentials require a nonempty username without ':' and a nonempty password"
            );
            Some(Credentials { username, password })
        }
        (None, None) => None,
        _ => bail!("set both {username_name} and {password_name}"),
    };
    let auth_origin = decode_env(host_name, auth_host)?
        .map(|host| parse_auth_origin(&host))
        .transpose()?;
    Ok((credentials, auth_origin))
}

fn decode_env(name: &str, value: Option<OsString>) -> Result<Option<String>> {
    value
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("{name} contains invalid Unicode"))
        })
        .transpose()
}

fn challenge_param(challenge: &ChallengeRef<'_>, name: &str) -> Option<String> {
    challenge
        .params
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.to_unescaped())
}

fn valid_target(base: &Url, target: &Url) -> bool {
    target.host().is_some()
        && target.username().is_empty()
        && target.password().is_none()
        && target.fragment().is_none()
        && (target.scheme() == "https" || target.origin() == base.origin())
}

fn registry_redirect(attempt: redirect::Attempt<'_>) -> redirect::Action {
    if attempt.previous().len() >= 10 {
        return attempt.error("too many registry redirects");
    }
    let previous = attempt
        .previous()
        .last()
        .expect("redirect has a source URL");
    let target = attempt.url();
    if !valid_target(previous, target) {
        return attempt.error("registry redirected to an unsafe URL");
    }
    // Reqwest strips authorization when a redirect changes the host or effective port.
    if previous.origin() != target.origin()
        && previous.host_str() == target.host_str()
        && previous.port_or_known_default() == target.port_or_known_default()
    {
        return attempt.error("registry redirect changed origin without changing host or port");
    }
    attempt.follow()
}

fn describe(media_type: &str, bytes: &[u8]) -> Descriptor {
    Descriptor {
        media_type: media_type.to_owned(),
        digest: Digest::sha256(bytes),
        size: bytes.len() as u64,
    }
}

fn content_type(response: &Response) -> Result<&str> {
    let value = response
        .headers()
        .get(CONTENT_TYPE)
        .context("registry response omitted its content type")?
        .to_str()?;
    Ok(value.split(';').next().unwrap_or_default().trim())
}

fn reported_digest(response: &Response) -> Result<Option<Digest>> {
    response
        .headers()
        .get(CONTENT_DIGEST)
        .map(|value| value.to_str()?.parse())
        .transpose()
}

fn verify_reported_digest(response: &Response, bytes: &[u8]) -> Result<()> {
    if let Some(digest) = reported_digest(response)? {
        digest
            .verify(bytes)
            .context("registry reported a different content digest")?;
    }
    Ok(())
}

fn read_body(response: Response, limit: u64, name: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {name}"))?;
    ensure!(bytes.len() as u64 <= limit, "{name} exceeds {limit} bytes");
    Ok(bytes)
}

fn expect_status(response: &Response, status: StatusCode, operation: &str) -> Result<()> {
    ensure!(
        response.status() == status,
        "could not {operation}: registry returned HTTP {}",
        response.status()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(values: &[(&str, &str)]) -> Result<(Option<Credentials>, Option<Url>)> {
        registry_environment(|name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        })
    }

    #[test]
    fn legacy_settings_are_used_together_without_current_settings() -> Result<()> {
        let [username, password, host] = LEGACY_REGISTRY_ENV;
        let (credentials, origin) = environment(&[
            (username, "legacy-user"),
            (password, "legacy-password"),
            (host, "auth.example.com:8443"),
        ])?;
        let credentials = credentials.expect("legacy credentials");
        assert_eq!(credentials.username, "legacy-user");
        assert_eq!(credentials.password.as_str(), "legacy-password");
        assert_eq!(origin.unwrap().as_str(), "https://auth.example.com:8443/");
        Ok(())
    }

    #[test]
    fn current_credentials_do_not_inherit_a_legacy_token_host() -> Result<()> {
        let [username, password, _] = REGISTRY_ENV;
        let [old_username, old_password, old_host] = LEGACY_REGISTRY_ENV;
        let (credentials, origin) = environment(&[
            (username, "current-user"),
            (password, "current-password"),
            (old_username, "legacy-user"),
            (old_password, "legacy-password"),
            (old_host, "legacy.example.com"),
        ])?;
        let credentials = credentials.expect("current credentials");
        assert_eq!(credentials.username, "current-user");
        assert_eq!(credentials.password.as_str(), "current-password");
        assert!(origin.is_none());
        Ok(())
    }

    #[test]
    fn a_current_token_host_does_not_inherit_legacy_credentials() -> Result<()> {
        let [_, _, host] = REGISTRY_ENV;
        let [old_username, old_password, _] = LEGACY_REGISTRY_ENV;
        let (credentials, origin) = environment(&[
            (host, "current.example.com"),
            (old_username, "legacy-user"),
            (old_password, "legacy-password"),
        ])?;
        assert!(credentials.is_none());
        assert_eq!(origin.unwrap().as_str(), "https://current.example.com/");
        Ok(())
    }

    #[test]
    fn partial_current_credentials_do_not_fall_back_to_legacy_credentials() {
        let [username, password, _] = REGISTRY_ENV;
        let [old_username, old_password, _] = LEGACY_REGISTRY_ENV;
        let error = environment(&[
            (username, "current-user"),
            (old_username, "legacy-user"),
            (old_password, "legacy-password"),
        ])
        .err()
        .expect("partial credentials are invalid");
        assert_eq!(
            error.to_string(),
            format!("set both {username} and {password}")
        );
    }
}
