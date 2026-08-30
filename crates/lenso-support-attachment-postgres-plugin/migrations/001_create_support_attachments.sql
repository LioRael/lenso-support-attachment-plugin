CREATE TABLE support_attachment_receipts (
    caller_instance TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('attach_content', 'upload_and_attach')),
    idempotency_key TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    receipt_id UUID NOT NULL UNIQUE,
    attachment_id UUID NOT NULL UNIQUE,
    upload_attempt SMALLINT NOT NULL DEFAULT 0 CHECK (upload_attempt BETWEEN 0 AND 16),
    status TEXT NOT NULL CHECK (status IN ('pending', 'committed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    committed_at TIMESTAMPTZ,
    PRIMARY KEY (caller_instance, operation, idempotency_key)
);

CREATE TABLE support_attachments (
    attachment_id UUID PRIMARY KEY,
    receipt_id UUID NOT NULL UNIQUE REFERENCES support_attachment_receipts(receipt_id),
    organization_id TEXT NOT NULL,
    case_id UUID NOT NULL,
    message_id UUID,
    content_id UUID NOT NULL,
    source_resource_type TEXT NOT NULL,
    source_resource_id TEXT NOT NULL,
    source_revision_id TEXT,
    filename TEXT NOT NULL,
    media_type TEXT NOT NULL CHECK (media_type IN ('image/png', 'image/jpeg', 'text/plain')),
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal')),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes BETWEEN 1 AND 1073741824),
    content_created_at TIMESTAMPTZ NOT NULL,
    attached_by_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX support_attachments_case_page
    ON support_attachments (organization_id, case_id, attachment_id);

CREATE INDEX support_attachments_message_page
    ON support_attachments (organization_id, case_id, message_id, attachment_id)
    WHERE message_id IS NOT NULL;

COMMENT ON TABLE support_attachments IS
    'Support Attachment-owned immutable associations; Content Vault owns bytes and protected keys.';
