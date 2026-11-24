# Contributing to DigestSeal

## Local checks

Install stable Rust and run these commands from the repository root. If you use `rustup`, install the formatter and linter with `rustup component add rustfmt clippy`.

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

`cargo test --locked` runs the unit tests and registry integration tests. The registry tests use a local fixture and require an environment that allows loopback TCP listeners.

## Changes

Keep pull requests focused and describe the behavior change and the checks you ran. When changing CLI usage, update the examples in [README.md](README.md). For a behavior change, a focused regression test helps reviewers see what changed.

Preserve compatibility with existing signature bundles and keys. If a change requires a new signature format, version it and document how existing bundles are handled. Keep the default signing algorithm and the sign-once reuse flow covered by tests.

## Releases

Set the package version in `Cargo.toml` using Semantic Versioning. Run `cargo check` to update `Cargo.lock`, then commit both files. [Semantic Versioning](https://semver.org/)

On the commit to release, create and push a tag that matches the package version with a `v` prefix. For version `0.1.0`, run these commands.

```sh
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

GitHub Actions checks the tag against the Cargo version, builds and tests the binaries, and publishes the archives and `SHA256SUMS` to GitHub Releases. A version with a prerelease suffix, such as `0.2.0-rc.1`, is published as a GitHub prerelease.
