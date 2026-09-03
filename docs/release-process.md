# Release process

Only `lenso-capability-support-attachment` is a public registry package. The
PostgreSQL implementation remains private to this repository.

Publication is manual-only from reviewed `main` through
`.github/workflows/release-plz.yml`. Repository pushes do not run release
automation. A live run requires `live=true`, the literal confirmation
`publish`, and `main`.

Before the first release, allocate the crate name on crates.io and configure
its Trusted Publisher:

- package: `lenso-capability-support-attachment`
- owner: `LioRael`
- repository: `lenso-support-attachment-plugin`
- workflow: `release-plz.yml`
- environment: unset

Only the confirmed live job receives `id-token: write`. The workflow has no
registry-token fallback.

## Required evidence

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
lenso-contract-codegen workspace check --manifest-path Cargo.toml
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
./scripts/check-repository-boundary.sh
cargo package --locked -p lenso-capability-support-attachment
```

Run the PostgreSQL acceptance test against a disposable database whose name
starts with `support_attachment_test` before publication. Generated Capability
projections are locked artifacts and must not be edited by hand.
