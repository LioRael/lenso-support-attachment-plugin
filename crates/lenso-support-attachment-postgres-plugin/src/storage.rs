use lenso_postgres_kit::OwnedPostgres;
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AttachmentRecord {
    pub attachment_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub message_id: Option<String>,
    pub content_id: String,
    pub filename: String,
    pub media_type: String,
    pub visibility: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub content_created_at: String,
    pub attached_by_subject: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingReceipt {
    pub receipt_id: Uuid,
    pub attachment_id: Uuid,
    pub upload_attempt: i16,
}

#[derive(Clone, Debug)]
pub(crate) enum Admission {
    Pending(PendingReceipt),
    Replay {
        receipt_id: String,
        attachment: Box<AttachmentRecord>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct NewAttachment<'a> {
    pub organization_id: &'a str,
    pub case_id: Uuid,
    pub message_id: Option<Uuid>,
    pub content_id: Uuid,
    pub source_resource_type: &'a str,
    pub source_resource_id: &'a str,
    pub source_revision_id: Option<&'a str>,
    pub filename: &'a str,
    pub media_type: &'a str,
    pub visibility: &'a str,
    pub sha256: &'a str,
    pub size_bytes: i64,
    pub content_created_at: OffsetDateTime,
    pub attached_by_subject: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    IdempotencyConflict,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("domain failure: {0:?}")]
    Domain(DomainFailure),
    #[error("database failure during {operation}: {source}")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("failed to format a timestamp: {0}")]
    Time(#[from] time::error::Format),
}

impl From<DomainFailure> for StorageError {
    fn from(value: DomainFailure) -> Self {
        Self::Domain(value)
    }
}

pub(crate) async fn admit_attach(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
) -> Result<Admission, StorageError> {
    let mut tx = begin(postgres, "begin attachment receipt admission").await?;
    let candidate_receipt = Uuid::now_v7();
    let candidate_attachment = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO support_attachment_receipts(caller_instance,operation,idempotency_key,request_hash,receipt_id,attachment_id,status) VALUES($1,$2,$3,$4,$5,$6,'pending') ON CONFLICT(caller_instance,operation,idempotency_key) DO NOTHING",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(request_hash)
    .bind(candidate_receipt)
    .bind(candidate_attachment)
    .execute(&mut *tx)
    .await
    .map_err(|source| database("insert attachment receipt", source))?;

    let row = sqlx::query(
        "SELECT request_hash,receipt_id,attachment_id,upload_attempt,status FROM support_attachment_receipts WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .fetch_one(&mut *tx)
    .await
    .map_err(|source| database("lock attachment receipt", source))?;
    let stored_hash: Vec<u8> = row
        .try_get("request_hash")
        .map_err(|source| database("decode attachment receipt hash", source))?;
    if stored_hash != request_hash {
        return Err(DomainFailure::IdempotencyConflict.into());
    }
    let receipt_id: Uuid = row
        .try_get("receipt_id")
        .map_err(|source| database("decode attachment receipt id", source))?;
    let attachment_id: Uuid = row
        .try_get("attachment_id")
        .map_err(|source| database("decode attachment id", source))?;
    let upload_attempt: i16 = row
        .try_get("upload_attempt")
        .map_err(|source| database("decode attachment upload attempt", source))?;
    let status: String = row
        .try_get("status")
        .map_err(|source| database("decode attachment receipt status", source))?;
    let admission =
        if status == "committed" {
            Admission::Replay {
                receipt_id: receipt_id.hyphenated().to_string(),
                attachment: Box::new(get_tx(&mut tx, attachment_id).await?.ok_or_else(|| {
                    database("load committed attachment", sqlx::Error::RowNotFound)
                })?),
            }
        } else {
            Admission::Pending(PendingReceipt {
                receipt_id,
                attachment_id,
                upload_attempt,
            })
        };
    commit(tx, "commit attachment receipt admission").await?;
    Ok(admission)
}

pub(crate) async fn finish_attach(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    pending: &PendingReceipt,
    value: &NewAttachment<'_>,
) -> Result<(String, AttachmentRecord, bool), StorageError> {
    let mut tx = begin(postgres, "begin attachment commit").await?;
    let row = sqlx::query(
        "SELECT request_hash,receipt_id,attachment_id,status FROM support_attachment_receipts WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .fetch_one(&mut *tx)
    .await
    .map_err(|source| database("lock attachment receipt for commit", source))?;
    let stored_hash: Vec<u8> = row
        .try_get("request_hash")
        .map_err(|source| database("decode attachment commit hash", source))?;
    let receipt_id: Uuid = row
        .try_get("receipt_id")
        .map_err(|source| database("decode attachment commit receipt", source))?;
    let attachment_id: Uuid = row
        .try_get("attachment_id")
        .map_err(|source| database("decode attachment commit id", source))?;
    let status: String = row
        .try_get("status")
        .map_err(|source| database("decode attachment commit status", source))?;
    if stored_hash != request_hash
        || receipt_id != pending.receipt_id
        || attachment_id != pending.attachment_id
    {
        return Err(DomainFailure::IdempotencyConflict.into());
    }
    if status == "committed" {
        let attachment = get_tx(&mut tx, attachment_id)
            .await?
            .ok_or_else(|| database("load replayed attachment", sqlx::Error::RowNotFound))?;
        commit(tx, "commit attachment replay").await?;
        return Ok((receipt_id.hyphenated().to_string(), attachment, true));
    }

    sqlx::query(
        "INSERT INTO support_attachments(attachment_id,receipt_id,organization_id,case_id,message_id,content_id,source_resource_type,source_resource_id,source_revision_id,filename,media_type,visibility,sha256,size_bytes,content_created_at,attached_by_subject) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
    )
    .bind(attachment_id)
    .bind(receipt_id)
    .bind(value.organization_id)
    .bind(value.case_id)
    .bind(value.message_id)
    .bind(value.content_id)
    .bind(value.source_resource_type)
    .bind(value.source_resource_id)
    .bind(value.source_revision_id)
    .bind(value.filename)
    .bind(value.media_type)
    .bind(value.visibility)
    .bind(value.sha256)
    .bind(value.size_bytes)
    .bind(value.content_created_at)
    .bind(value.attached_by_subject)
    .execute(&mut *tx)
    .await
    .map_err(|source| database("insert support attachment", source))?;
    sqlx::query(
        "UPDATE support_attachment_receipts SET status='committed',committed_at=clock_timestamp() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .execute(&mut *tx)
    .await
    .map_err(|source| database("commit attachment receipt", source))?;
    let attachment = get_tx(&mut tx, attachment_id)
        .await?
        .ok_or_else(|| database("load inserted attachment", sqlx::Error::RowNotFound))?;
    commit(tx, "commit support attachment").await?;
    Ok((receipt_id.hyphenated().to_string(), attachment, false))
}

pub(crate) async fn advance_upload_attempt(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    pending: &PendingReceipt,
) -> Result<PendingReceipt, StorageError> {
    let row = sqlx::query(
        "UPDATE support_attachment_receipts SET upload_attempt=upload_attempt+1 WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 AND request_hash=$4 AND receipt_id=$5 AND attachment_id=$6 AND status='pending' AND upload_attempt=$7 AND upload_attempt<16 RETURNING upload_attempt",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(request_hash)
    .bind(pending.receipt_id)
    .bind(pending.attachment_id)
    .bind(pending.upload_attempt)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|source| database("advance attachment upload attempt", source))?
    .ok_or_else(|| database("advance attachment upload attempt", sqlx::Error::RowNotFound))?;
    let upload_attempt: i16 = row
        .try_get("upload_attempt")
        .map_err(|source| database("decode advanced upload attempt", source))?;
    Ok(PendingReceipt {
        receipt_id: pending.receipt_id,
        attachment_id: pending.attachment_id,
        upload_attempt,
    })
}

pub(crate) async fn get_attachment(
    postgres: &OwnedPostgres,
    organization_id: &str,
    case_id: Uuid,
    attachment_id: Uuid,
) -> Result<Option<AttachmentRecord>, StorageError> {
    let row = sqlx::query(
        "SELECT * FROM support_attachments WHERE organization_id=$1 AND case_id=$2 AND attachment_id=$3",
    )
    .bind(organization_id)
    .bind(case_id)
    .bind(attachment_id)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|source| database("get support attachment", source))?;
    row.as_ref().map(decode_attachment).transpose()
}

pub(crate) async fn list_attachments(
    postgres: &OwnedPostgres,
    organization_id: &str,
    case_id: Uuid,
    message_id: Option<Uuid>,
    after: Option<Uuid>,
    include_internal: bool,
    limit: i64,
) -> Result<Vec<AttachmentRecord>, StorageError> {
    let rows = sqlx::query(
        "SELECT * FROM support_attachments WHERE organization_id=$1 AND case_id=$2 AND ($3::uuid IS NULL OR message_id=$3) AND ($4 OR visibility='public') AND ($5::uuid IS NULL OR attachment_id>$5) ORDER BY attachment_id LIMIT $6",
    )
    .bind(organization_id)
    .bind(case_id)
    .bind(message_id)
    .bind(include_internal)
    .bind(after)
    .bind(limit)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list support attachments", source))?;
    rows.iter().map(decode_attachment).collect()
}

async fn get_tx(
    tx: &mut Transaction<'_, Postgres>,
    attachment_id: Uuid,
) -> Result<Option<AttachmentRecord>, StorageError> {
    let row = sqlx::query("SELECT * FROM support_attachments WHERE attachment_id=$1")
        .bind(attachment_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|source| database("get support attachment in transaction", source))?;
    row.as_ref().map(decode_attachment).transpose()
}

fn decode_attachment(row: &sqlx::postgres::PgRow) -> Result<AttachmentRecord, StorageError> {
    let attachment_id: Uuid = row
        .try_get("attachment_id")
        .map_err(|source| database("decode attachment id", source))?;
    let case_id: Uuid = row
        .try_get("case_id")
        .map_err(|source| database("decode attachment case id", source))?;
    let message_id: Option<Uuid> = row
        .try_get("message_id")
        .map_err(|source| database("decode attachment message id", source))?;
    let content_id: Uuid = row
        .try_get("content_id")
        .map_err(|source| database("decode attachment content id", source))?;
    let content_created_at: OffsetDateTime = row
        .try_get("content_created_at")
        .map_err(|source| database("decode content creation time", source))?;
    let created_at: OffsetDateTime = row
        .try_get("created_at")
        .map_err(|source| database("decode attachment creation time", source))?;
    Ok(AttachmentRecord {
        attachment_id: attachment_id.hyphenated().to_string(),
        organization_id: row
            .try_get("organization_id")
            .map_err(|source| database("decode attachment organization", source))?,
        case_id: case_id.hyphenated().to_string(),
        message_id: message_id.map(|value| value.hyphenated().to_string()),
        content_id: content_id.hyphenated().to_string(),
        filename: row
            .try_get("filename")
            .map_err(|source| database("decode attachment filename", source))?,
        media_type: row
            .try_get("media_type")
            .map_err(|source| database("decode attachment media type", source))?,
        visibility: row
            .try_get("visibility")
            .map_err(|source| database("decode attachment visibility", source))?,
        sha256: row
            .try_get("sha256")
            .map_err(|source| database("decode attachment digest", source))?,
        size_bytes: row
            .try_get("size_bytes")
            .map_err(|source| database("decode attachment size", source))?,
        content_created_at: content_created_at.format(&Rfc3339)?,
        attached_by_subject: row
            .try_get("attached_by_subject")
            .map_err(|source| database("decode attachment actor", source))?,
        created_at: created_at.format(&Rfc3339)?,
    })
}

async fn begin<'a>(
    postgres: &'a OwnedPostgres,
    operation: &'static str,
) -> Result<Transaction<'a, Postgres>, StorageError> {
    postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database(operation, source))
}

async fn commit(
    tx: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), StorageError> {
    tx.commit()
        .await
        .map_err(|source| database(operation, source))
}

fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}
