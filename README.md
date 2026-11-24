# DigestSeal

<img src="logo.png" alt="DigestSeal logo" width="540">

DigestSeal is a Rust CLI for signing OCI images. It defaults to NIST ML-DSA-65 and supports opt-in Ed25519 and ECDSA P-256. It saves a detached signature bundle and attaches it to the image as an OCI referrer. Tags, repositories, and registries can change while the same bundle stays valid for the exact image digest.

## Install

Download the archive for your platform and verify it against the release's `SHA256SUMS` file. Extract `digestseal` (or `digestseal.exe` on Windows) and put it on your `PATH`. Releases include Linux and macOS binaries for x86-64 and ARM64, plus a Windows x86-64 binary. The Linux binaries are built against glibc on Ubuntu 24.04. [GitHub Releases](https://github.com/abhishekamralkar/digestseal/releases)

## Build

```sh
cargo build --release --locked
```

The binary is `target/release/digestseal`. Put it on your `PATH` for the examples below.

## Sign once and promote

```sh
digestseal keygen --private-key signing.key.pem --public-key signing.pub.pem

digestseal sign --key signing.key.pem --bundle app.sig.json \
  registry.example.com/build/app:1.0

# Set DIGEST to the digest printed by the sign command.
oras cp "registry.example.com/build/app@${DIGEST}" registry.example.com/prod/app:1.0

digestseal reuse --bundle app.sig.json --public-key signing.pub.pem \
  "registry.example.com/prod/app@${DIGEST}"
```

`sign` resolves the tag once, signs the manifest or multi-platform index it points to, and saves the bundle before uploading it. It prints the digest-pinned image reference. Use that reference when copying or deploying an image so a moving tag cannot select a different build. Use `--bundle-only` with pull access to defer publication. If publication fails after saving the bundle, run `reuse` with the saved bundle and the original digest-pinned reference to retry.

`reuse` authenticates the bundle with the supplied trusted public key and compares the destination manifest with the signed manifest. If they match, it publishes the original bundle bytes, so promotion jobs need only the public key and destination registry access. The same bundle and subject produce the same referrer digest on retries. If the destination uses a different digest algorithm for tags, address it by the original signed digest. Image conversions that rewrite the manifest produce a new digest and require a new signature.

## Signing algorithms

`keygen`, `sign`, and `reuse` default to `ml-dsa-65`, including when reusing an existing ML-DSA-65 bundle. For a classical key and bundle, pass the same `--algorithm` value to all three commands.

```sh
digestseal keygen --algorithm ed25519 --private-key signing.key.pem --public-key signing.pub.pem
```

An existing Ed25519 or P-256 key pair in the PEM formats below can be used directly with `sign` and `reuse`.

| `--algorithm` | Signed `algorithm` value | Signature |
| --- | --- | --- |
| `ml-dsa-65` | `ML-DSA-65` | Hedged pure ML-DSA-65 with an empty context |
| `ed25519` | `Ed25519` | Raw 64-byte Ed25519 signature |
| `ecdsa-p256` | `ECDSA-P256-SHA256` | ASN.1 DER ECDSA P-256 signature using SHA-256 |

## Registry access

Registry requests use HTTPS and can start anonymously. For private registries, set `DIGESTSEAL_REGISTRY_USERNAME` and `DIGESTSEAL_REGISTRY_PASSWORD` in the command's environment. Use a registry token as the password where supported. Grant pull access to resolve the image and push access to publish its referrer. For a registry with a separate trusted HTTPS token service, set `DIGESTSEAL_REGISTRY_AUTH_HOST` to that service's hostname and optional port. Docker Hub's token host is recognized automatically. `--plain-http` enables HTTP for a local test registry.

DigestSeal reads the corresponding legacy `MICROSIGN_REGISTRY_*` variables when all three `DIGESTSEAL_REGISTRY_*` settings are unset.

For registries that use referrers tags and ignore conditional updates, serialize publication of different signatures for the same repository and subject digest to protect the shared index.

## Signature format and compliance

- Private keys use unencrypted PKCS#8 PEM and are created with `0600` permissions on Unix. Public keys use SubjectPublicKeyInfo (SPKI) PEM. ML-DSA-65 private keys use the RFC 9881 seed form. Distribute the public key through a trusted channel. [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html)
- The bundle is a single-signature DSSE JSON envelope with payload type `application/vnd.microsign.image-signature.payload.v1+json`. The signed JSON includes `algorithm`, `subject` (the OCI descriptor with `mediaType`, `digest`, and `size`), and `manifestSha512` (the `sha512:` digest of the raw manifest bytes). The optional DSSE `keyid` gives the SHA-256 fingerprint of the public SPKI DER. Consumers can verify the DSSE message using the matching signature algorithm and a trusted public key. [DSSE protocol](https://github.com/dsse-lf/dsse/blob/master/protocol.md)
- The OCI artifact type and bundle layer media type are both `application/vnd.microsign.signature.v1+json`. To find it, run `oras discover --artifact-type application/vnd.microsign.signature.v1+json IMAGE`. DigestSeal retains the original media types so existing bundles remain discoverable and reusable. [OCI image manifest specification](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md) · [OCI distribution specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)

ML-DSA-65 is the post-quantum signing option standardized in FIPS 204. Ed25519 and ECDSA P-256 are classical signature algorithms. FIPS 140-3 module validation requires separate certification. The registry's transport and the digest algorithms in the OCI image graph remain part of the surrounding deployment. [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [NIST Cryptographic Module Validation Program](https://csrc.nist.gov/projects/cryptographic-module-validation-program)

## Contributing

Run `cargo test --locked` to check signing, key handling, and registry reuse. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full set of local checks.

## License

DigestSeal is licensed under the [Apache License 2.0](LICENSE). Its dependencies are distributed under their respective licenses.
