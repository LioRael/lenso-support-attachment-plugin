# Agent instructions

This repository owns `lenso.support-attachment@1` and the removable Support
Attachment Plugin.

- Keep case and message facts in Support Case. This Plugin owns only attachment
  associations, user-facing filename/media-type/visibility metadata, immutable
  Content Vault references, and idempotency receipts.
- Every case decision must go through the bound
  `lenso.support-case-authorization@1` Provider. Never read Support Case tables.
- Never expose Content Vault protected object keys or add protected-blob
  deletion. Content bytes remain owned by Content Vault.
- The Capability descriptor and package-local JSON Schemas are authoritative;
  never hand-edit generated projections.
- PostgreSQL acceptance tests require
  `LENSO_SUPPORT_ATTACHMENT_TEST_DATABASE_URL` and must target a database whose
  name starts with `support_attachment_test`.
- Run Cargo through
  `/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo`.
- Registry publication, remote creation, commits, pushes, and releases require
  explicit approval.
