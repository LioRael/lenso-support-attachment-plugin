use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Executor as _};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{SupportAttachmentOperator, schema, storage};

#[tokio::test]
#[allow(clippy::too_many_lines)] // One restart scenario is easier to audit as one sequence.
async fn receipts_and_visibility_survive_restart() {
    let Ok(database_url) = std::env::var("LENSO_SUPPORT_ATTACHMENT_TEST_DATABASE_URL") else {
        return;
    };
    let database_name = Url::parse(&database_url)
        .ok()
        .and_then(|url| {
            url.path_segments()
                .and_then(Iterator::last)
                .map(str::to_owned)
        })
        .expect("acceptance database URL must contain a database name");
    assert!(
        database_name.starts_with("support_attachment_test"),
        "acceptance database name must start with support_attachment_test"
    );
    let schema_name = format!("support_attachment_test_{}", Uuid::now_v7().simple());
    SupportAttachmentOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();

    let pending = match storage::admit_attach(
        &postgres,
        "support-web",
        "attach_content",
        "attach-1",
        &[1, 2, 3],
    )
    .await
    .unwrap()
    {
        storage::Admission::Pending(value) => value,
        storage::Admission::Replay { .. } => panic!("first admission cannot replay"),
    };
    let upload_pending = match storage::admit_attach(
        &postgres,
        "support-web",
        "upload_and_attach",
        "attach-1",
        &[9, 8, 7],
    )
    .await
    .unwrap()
    {
        storage::Admission::Pending(value) => value,
        storage::Admission::Replay { .. } => panic!("different operation cannot replay"),
    };
    let advanced = storage::advance_upload_attempt(
        &postgres,
        "support-web",
        "upload_and_attach",
        "attach-1",
        &[9, 8, 7],
        &upload_pending,
    )
    .await
    .unwrap();
    assert_eq!(advanced.upload_attempt, 1);
    assert_eq!(advanced.receipt_id, upload_pending.receipt_id);
    assert_eq!(advanced.attachment_id, upload_pending.attachment_id);
    let case_id = Uuid::now_v7();
    let content_id = Uuid::now_v7();
    let (_, created, replayed) = storage::finish_attach(
        &postgres,
        "support-web",
        "attach_content",
        "attach-1",
        &[1, 2, 3],
        &pending,
        &storage::NewAttachment {
            organization_id: "org-1",
            case_id,
            message_id: None,
            content_id,
            source_resource_type: "support_attachment_staging",
            source_resource_id: "upload-1",
            source_revision_id: None,
            filename: "customer-log.txt",
            media_type: "text/plain",
            visibility: "internal",
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            size_bytes: 42,
            content_created_at: OffsetDateTime::now_utc(),
            attached_by_subject: "usr-agent",
        },
    )
    .await
    .unwrap();
    assert!(!replayed);
    postgres.pool().close().await;

    let restarted = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    let replay = storage::admit_attach(
        &restarted,
        "support-web",
        "attach_content",
        "attach-1",
        &[1, 2, 3],
    )
    .await
    .unwrap();
    assert!(matches!(
        replay,
        storage::Admission::Replay { attachment, .. }
            if attachment.attachment_id == created.attachment_id
    ));
    let public = storage::list_attachments(&restarted, "org-1", case_id, None, None, false, 10)
        .await
        .unwrap();
    assert!(public.is_empty());
    let internal = storage::list_attachments(&restarted, "org-1", case_id, None, None, true, 10)
        .await
        .unwrap();
    assert_eq!(internal.len(), 1);
    assert!(matches!(
        storage::admit_attach(
            &restarted,
            "support-web",
            "attach_content",
            "attach-1",
            &[9],
        )
        .await,
        Err(storage::StorageError::Domain(
            storage::DomainFailure::IdempotencyConflict
        ))
    ));

    restarted.pool().close().await;
    let cleanup = sqlx::PgPool::connect(&database_url).await.unwrap();
    cleanup
        .execute(AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema_name}\" CASCADE"
        )))
        .await
        .unwrap();
    cleanup.close().await;
}
