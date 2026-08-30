# Support Attachment v1 Plugin card

## Owner and deletion boundary

The Plugin owns attachment rows, case/message association metadata, filename,
media type, visibility, Content Vault IDs/descriptors, and idempotency receipts.
Removing its Instance, package, owned schema, and Vault claims removes Support
Attachment behavior without deleting Support Case records or directly deleting
protected content.

## Contract

`lenso.support-attachment@1` is portable and cross-lane transferable with four
request Operations: `attach_content`, `upload_and_attach`, `list_attachments`,
and `get_attachment`. `upload_and_attach` carries sensitive portable bytes
bounded to 8 MiB and currently accepts only `text/plain`; no operation carries a
storage key. Domain errors cover authentication/authorization, invalid
requests, rejected or mismatched content, missing attachments, and idempotency
conflicts. Provider loss, deadline, cancellation, storage failure, and
inconsistent dependency output remain Runtime Failures.

## Authorization

The Plugin authenticates the exact Support Attachment audience and admits only
configured caller Instances. It then calls the bound
`lenso.support-case-authorization@1` Provider with the verified subject,
organization, case reference, optional message ID, and one explicit action:

- `read_public`
- `read_internal`
- `attach_public`
- `attach_internal`

Support Case resolves the canonical case UUID, validates an optional message
association, and makes the final requester/membership/permission decision.
Absent, unrelated, and forbidden resources do not become distinguishable
through this Plugin. App composition must configure this exact Support
Attachment Instance in the Support Case Authorization Provider's
`resource_callers`; wildcard admission is not supported.

## Content Vault saga

The source and target grants both name this exact Plugin Instance, satisfying
the current Content Vault owner boundary. A durable pending receipt fixes the
receipt and attachment UUIDs before external calls. For `upload_and_attach`, it
also persists an attempt number used in a deterministic Vault reservation key;
the Plugin resumes at the returned offset and advances the attempt, up to 16,
when a session expires. For `attach_content`, it describes the caller-staged
object. Both paths then make the idempotent claim. The PostgreSQL commit installs
the association and marks the receipt committed atomically; later replay
returns the stored response.

The original upload owner is retained. This prevents accidental protected blob
deletion and is an explicit v1 retention cost, not a hidden cleanup promise.

## Lifecycle and state

PostgreSQL is the only association/receipt state. Setup and upgrade are operator
workflows; activation resolves Secrets and verifies the existing schema. The
Plugin stores the immutable App-local Instance key from `ActivateContext` for
Vault owner grants. Deactivation closes the generation-owned pool.

## Known prerequisite

Local validation uses Auth SDK, Support Case Authorization, and Content Vault
packages from aligned sibling worktrees. Their exact common baseline is
protocols `9d2774c767fd64a6cc63a5ac04360e9cb92816da`, core
`8599db7e4a214ed92f32089f81d14c833d4becf6`, and runtime
`89815107385475c8b5be378bdcf5e21aa74e02f0`. Publication requires those owner
packages to publish immutable artifacts on that baseline, after which this
Plugin's temporary path dependencies can be replaced. Handwritten dispatch and
duplicated Auth verification remain out of scope.
