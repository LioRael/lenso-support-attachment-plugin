# Lenso Support Attachment Plugin

`lenso-support-attachment-plugin` is a removable, PostgreSQL-backed Lenso
Plugin for attaching immutable Content Vault objects to support cases and
messages. It provides the portable `lenso.support-attachment@1` Capability.

The Plugin owns attachment associations, display filename, media type,
visibility, the immutable Content Vault reference, and durable idempotency
receipts. Support Case remains the source of truth for cases, messages, and
their final resource authorization. Content Vault remains the source of truth
for bytes, integrity, claims, and protected storage keys.

## Operations

- `attach_content` requests explicit `attach_public` or `attach_internal`
  authority through `lenso.support-case-authorization@1`, describes an existing
  Vault object, verifies the declared media type, claims it for a stable
  attachment owner, and atomically commits the association and receipt.
- `upload_and_attach` accepts 1 byte through 8 MiB of portable `text/plain`
  content, authorizes the case/message attachment, then reserves, resumes,
  uploads, commits, and claims the Content Vault object before atomically
  committing the association. Its durable receipt makes an interrupted flow
  retryable without publishing an attachment row early.
- `list_attachments` returns a bounded UUID-v7 keyset page. Public access and
  internal-note access are authorized independently; requester relationship
  never exposes internal attachments.
- `get_attachment` returns attachment metadata after case authorization. It
  does not return bytes, credentials, or an object-store key.

Every operation requires an exact configured caller and an Auth assertion for
the exact Support Attachment operation. The Plugin passes the verified subject
to the exact bound Support Case Authorization Provider. It never opens or
queries a Support Case table.

## Content handoff

`upload_and_attach` is the directly reachable ingress. It accepts portable
bytes from an authenticated configured caller and creates the Vault source
under this Support Attachment Instance:

```text
plugin_instance = <this support-attachment instance>
resource_type = support_attachment_upload
resource_id = <durable receipt UUID>
```

The Plugin uses a deterministic reservation key per receipt attempt and resumes
at the Vault-provided offset. An expired session advances the persisted attempt
(bounded to 16) and retries with a new reservation key. It accepts an
attachment row only after Vault commit and an active idempotent claim to
`resource_type=support_attachment` and `resource_id=<attachment UUID>`. It does
not expose a protected storage key, release the original upload owner, or delete
protected bytes. A separately reviewed retention protocol is required before
either behavior can be added.

`attach_content` remains available for content already created under this same
Plugin Instance. That operation can associate `image/png`, `image/jpeg`, or
`text/plain` descriptors. Content Vault's current public upload stream accepts
only `text/plain`, so `upload_and_attach` intentionally exposes only that media
type.

## Configuration and dependencies

One Instance requires exactly one Provider for each of:

- `lenso.secrets@1`
- `lenso.content-vault@1`
- `lenso.support-case-authorization@1`

Configuration supplies the owned PostgreSQL schema, one logical database URL
secret reference, Auth assertion verifier metadata, and 1–64 exact business
caller Instance keys. Runtime activation verifies the authored schema and
never runs DDL. Use `SupportAttachmentOperator::setup` and `upgrade` explicitly.
The App must also list this Support Attachment Instance as an exact
`resource_callers` entry on the selected Support Case Authorization Provider;
there is no wildcard or table-level fallback.

## Verification

```bash
cargo fmt \
  -p lenso-capability-support-attachment \
  -p lenso-support-attachment-postgres-plugin -- --check
cargo check \
  --workspace --all-targets --all-features
cargo test \
  --workspace --all-targets --all-features
cargo clippy \
  --workspace --all-targets --all-features -- -D warnings
lenso-contract-codegen workspace check --manifest-path Cargo.toml
./scripts/check-repository-boundary.sh
```

PostgreSQL acceptance is opt-in and rejects an obviously unrelated database
URL:

```bash
LENSO_SUPPORT_ATTACHMENT_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/support_attachment_test \
  cargo test \
  -p lenso-support-attachment-postgres-plugin \
  --features postgres-acceptance postgres_tests::
```

## Delivery status

This source release includes a real Kernel calling-chain test that invokes the
generated Support Attachment endpoint and generated Content Vault Client/Port
through reserve, upload stream commit, and claim while asserting that the Vault
sees this attachment Instance as both source and target owner.

The Auth SDK, Support Case Authorization Capability, and Content Vault
Capability are consumed from immutable remote revisions for clean-checkout
validation.
The exact suite baseline is protocols
`9d2774c767fd64a6cc63a5ac04360e9cb92816da`, core
`8599db7e4a214ed92f32089f81d14c833d4becf6`, and runtime
`89815107385475c8b5be378bdcf5e21aa74e02f0`. Crates.io publication remains
deferred until those owner packages publish compatible registry artifacts.
