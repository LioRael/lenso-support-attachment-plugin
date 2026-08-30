//! PostgreSQL-backed Support Attachment behavior with Support Case-owned authorization.

#[cfg(test)]
mod calling_chain_tests;
mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_content_vault as vault;
use lenso_capability_content_vault::{
    ClaimError, ClaimRequest, ContentDescriptor, ContentVaultClaimInvocationError,
    ContentVaultDescribeInvocationError, ContentVaultReserveInvocationError,
    ContentVaultUploadInvocationError, DescribeError, DescribeRequest, Owner, OwnerGrant,
    ReserveError, ReserveRequest, UploadError, UploadFrame, UploadFrameKind, UploadRequest,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_capability_support_attachment as attachment;
use lenso_capability_support_attachment::{
    AttachContentError, AttachContentRequest, AttachContentResponse, Attachment,
    AttachmentMediaType, AttachmentVisibility, GetAttachmentError, GetAttachmentRequest,
    GetAttachmentResponse, ListAttachmentsError, ListAttachmentsRequest, ListAttachmentsResponse,
    MediaType, UploadAndAttachError, UploadAndAttachRequest, UploadAndAttachResponse,
    UploadContentType, Visibility,
};
use lenso_capability_support_case_authorization as case_authorization;
use lenso_capability_support_case_authorization::{
    AuthorizeCaseAccessRequest, AuthorizeCaseAccessRequestAction,
    SupportCaseAuthorizationInvocationError,
};
use lenso_kernel::{PluginDependencies, RuntimeFailure, StreamEvent};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::storage::{Admission, DomainFailure, NewAttachment, StorageError};

pub use operator::{SupportAttachmentOperator, SupportAttachmentOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_ORGANIZATION_CHARS: usize = 200;
const MAX_CASE_REF_CHARS: usize = 500;
const MAX_OWNER_TYPE_CHARS: usize = 200;
const MAX_OWNER_ID_CHARS: usize = 500;
const MAX_IDEMPOTENCY_CHARS: usize = 300;
const MAX_FILENAME_CHARS: usize = 255;
const MAX_INLINE_UPLOAD_BYTES: usize = 8 * 1024 * 1024;
const UPLOAD_RESERVATION_TTL_SECONDS: i64 = 86_400;

/// Immutable configuration for one Support Attachment Plugin Instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportAttachmentConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    business_callers: Vec<String>,
}

impl SupportAttachmentConfig {
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        business_callers: Vec<String>,
    ) -> Result<Self, SupportAttachmentConfigError> {
        let config = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            business_callers,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), SupportAttachmentConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| SupportAttachmentConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(SupportAttachmentConfigError::InvalidSecretReference);
        }
        if !valid_identifier(&self.auth_issuer, 256) {
            return Err(SupportAttachmentConfigError::InvalidAuthIssuer);
        }
        if !(1..=4096).contains(&self.auth_assertion_public_key.len()) {
            return Err(SupportAttachmentConfigError::InvalidAuthPublicKey);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| SupportAttachmentConfigError::InvalidAuthPublicKey)?;
        validate_callers(&self.business_callers)
            .map_err(|()| SupportAttachmentConfigError::InvalidBusinessCallers)
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Support Attachment Auth verification key is invalid".to_owned(),
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SupportAttachmentConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("business_callers must contain 1 to 64 unique exact Instance keys")]
    InvalidBusinessCallers,
}

fn validate_config(config: &SupportAttachmentConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Support Attachment configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedSupportAttachment {
    postgres: OwnedPostgres,
    instance_key: String,
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct PostgresSupportAttachmentPlugin {
    #[config]
    config: SupportAttachmentConfig,
    secrets: Port<secrets::SecretsClient>,
    content_vault: Port<vault::ContentVaultClient>,
    case_authorization: Port<case_authorization::SupportCaseAuthorizationClient>,
    prepared: Rc<RefCell<Option<PreparedSupportAttachment>>>,
}

impl fmt::Debug for PostgresSupportAttachmentPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresSupportAttachmentPlugin")
            .field("schema", &self.config.schema)
            .field("prepared", &self.prepared.borrow().is_some())
            .field("business_caller_count", &self.config.business_callers.len())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(attachment::SupportAttachment)]
impl PostgresSupportAttachmentPlugin {}

impl PostgresSupportAttachmentPlugin {
    fn prepared(&self) -> Result<PreparedSupportAttachment, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Support Attachment Plugin is not prepared".to_owned(),
            })
    }

    fn authenticate(
        &self,
        context: &Ctx,
        operation: &str,
    ) -> Result<AuthorizedCaller, AuthenticationFailure> {
        let caller = context
            .caller_instance()
            .filter(|caller| {
                self.config
                    .business_callers
                    .iter()
                    .any(|allowed| allowed == caller)
            })
            .ok_or(AuthenticationFailure::Forbidden)?
            .to_owned();
        let actor = self
            .config
            .verifier()
            .map_err(AuthenticationFailure::Runtime)?
            .project_context::<SupportAttachmentActor>(
                context,
                attachment::CAPABILITY_ID,
                operation,
                &UtcClock,
            )
            .map_err(|_| AuthenticationFailure::Unauthenticated)?;
        valid_bounded(&actor.subject, 500)
            .then_some(AuthorizedCaller {
                caller,
                subject: actor.subject,
            })
            .ok_or(AuthenticationFailure::Unauthenticated)
    }

    async fn authorize_case(
        &self,
        context: &Ctx,
        organization_id: &str,
        case_ref: &str,
        message_id: Option<&str>,
        subject: &str,
        action: AuthorizeCaseAccessRequestAction,
    ) -> Result<Uuid, CaseAuthorizationFailure> {
        let response = self
            .case_authorization
            .authorize_case_access_with_context(
                context.clone(),
                AuthorizeCaseAccessRequest {
                    action,
                    case_ref: case_ref.to_owned(),
                    message_id: message_id.map(str::to_owned),
                    organization_id: organization_id.to_owned(),
                    subject: subject.to_owned(),
                },
            )
            .await
            .map_err(|error| match error {
                SupportCaseAuthorizationInvocationError::Domain(_) => {
                    CaseAuthorizationFailure::Forbidden
                }
                SupportCaseAuthorizationInvocationError::Runtime(error) => {
                    CaseAuthorizationFailure::Runtime(error)
                }
            })?;
        if !response.allowed {
            return Err(CaseAuthorizationFailure::Forbidden);
        }
        response
            .case_id
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| {
                CaseAuthorizationFailure::Runtime(RuntimeFailure::PluginFailure {
                    detail: "Support Case Authorization allowed access without a valid case id"
                        .to_owned(),
                })
            })
    }

    #[allow(clippy::too_many_lines)] // Keep the externally visible saga ordered in one place.
    async fn attach_content(
        &self,
        context: Ctx,
        request: AttachContentRequest,
    ) -> PluginResult<AttachContentResponse, AttachContentError> {
        let authorized = self
            .authenticate(&context, attachment::ATTACH_CONTENT_OPERATION)
            .map_err(map_attach_authentication)?;
        validate_attach_request(&request)
            .then_some(())
            .ok_or_else(|| PluginError::domain(AttachContentError::InvalidRequest))?;
        let action = match request.visibility {
            Visibility::Public => AuthorizeCaseAccessRequestAction::AttachPublic,
            Visibility::Internal => AuthorizeCaseAccessRequestAction::AttachInternal,
        };
        let case_id = self
            .authorize_case(
                &context,
                &request.organization_id,
                &request.case_ref,
                request.message_id.as_deref(),
                &authorized.subject,
                action,
            )
            .await
            .map_err(map_attach_case_authorization)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let request_hash = hash_request(&request).map_err(PluginError::runtime)?;
        let admission = storage::admit_attach(
            &prepared.postgres,
            &authorized.caller,
            attachment::ATTACH_CONTENT_OPERATION,
            &request.idempotency_key,
            &request_hash,
        )
        .await
        .map_err(map_attach_storage)?;
        let pending = match admission {
            Admission::Replay {
                receipt_id,
                attachment,
            } => {
                return Ok(AttachContentResponse {
                    attachment: contract_attachment(*attachment).map_err(PluginError::runtime)?,
                    receipt_id,
                    replayed: true,
                });
            }
            Admission::Pending(pending) => pending,
        };

        let grant = OwnerGrant {
            actor_id: authorized.subject.clone(),
            correlation_id: context.request_id().to_string(),
            owner: Owner {
                plugin_instance: prepared.instance_key.clone(),
                resource_id: request.source.resource_id.clone(),
                resource_type: request.source.resource_type.clone(),
                revision_id: Some(request.source.revision_id.clone()),
            },
            tenant_id: request.organization_id.clone(),
        };
        let descriptor = self
            .content_vault
            .describe_with_context(
                context.clone(),
                DescribeRequest {
                    content_id: request.content_id.clone(),
                    grant: grant.clone(),
                },
            )
            .await
            .map_err(map_describe_failure)?
            .content;
        let requested_media_type = media_type(&request.media_type);
        if descriptor.content_id != request.content_id
            || descriptor.media_type != requested_media_type
        {
            return Err(PluginError::domain(AttachContentError::ContentMismatch));
        }
        let claim = self
            .content_vault
            .claim_with_context(
                context,
                ClaimRequest {
                    content_id: request.content_id.clone(),
                    grant,
                    role: "support_attachment".to_owned(),
                    target: Owner {
                        plugin_instance: prepared.instance_key.clone(),
                        resource_id: pending.attachment_id.hyphenated().to_string(),
                        resource_type: "support_attachment".to_owned(),
                        revision_id: Some(None),
                    },
                },
            )
            .await
            .map_err(map_claim_failure)?;
        if !claim.active {
            return Err(PluginError::runtime(RuntimeFailure::PluginFailure {
                detail: "Content Vault returned an inactive attachment claim".to_owned(),
            }));
        }
        let content_id = Uuid::parse_str(&descriptor.content_id)
            .map_err(|_| invalid_vault_descriptor("content id"))?;
        let content_created_at = OffsetDateTime::parse(&descriptor.created_at, &Rfc3339)
            .map_err(|_| invalid_vault_descriptor("creation timestamp"))?;
        let message_id = request
            .message_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| PluginError::domain(AttachContentError::InvalidRequest))?;
        let visibility = visibility(&request.visibility);
        let (receipt_id, record, replayed) = storage::finish_attach(
            &prepared.postgres,
            &authorized.caller,
            attachment::ATTACH_CONTENT_OPERATION,
            &request.idempotency_key,
            &request_hash,
            &pending,
            &NewAttachment {
                organization_id: &request.organization_id,
                case_id,
                message_id,
                content_id,
                source_resource_type: &request.source.resource_type,
                source_resource_id: &request.source.resource_id,
                source_revision_id: request.source.revision_id.as_deref(),
                filename: &request.filename,
                media_type: requested_media_type,
                visibility,
                sha256: &descriptor.sha256,
                size_bytes: descriptor.size_bytes,
                content_created_at,
                attached_by_subject: &authorized.subject,
            },
        )
        .await
        .map_err(map_attach_storage)?;
        Ok(AttachContentResponse {
            attachment: contract_attachment(record).map_err(PluginError::runtime)?,
            receipt_id,
            replayed,
        })
    }

    #[allow(clippy::too_many_lines)] // Keep the externally visible saga ordered in one place.
    async fn upload_and_attach(
        &self,
        context: Ctx,
        request: UploadAndAttachRequest,
    ) -> PluginResult<UploadAndAttachResponse, UploadAndAttachError> {
        let authorized = self
            .authenticate(&context, attachment::UPLOAD_AND_ATTACH_OPERATION)
            .map_err(map_upload_authentication)?;
        if !validate_upload_and_attach_request(&request) {
            return Err(PluginError::domain(UploadAndAttachError::InvalidRequest));
        }
        if !matches!(
            std::str::from_utf8(request.content.as_slice()),
            Ok(text) if !text.contains('\0')
        ) {
            return Err(PluginError::domain(UploadAndAttachError::ContentRejected));
        }
        let action = match request.visibility {
            Visibility::Public => AuthorizeCaseAccessRequestAction::AttachPublic,
            Visibility::Internal => AuthorizeCaseAccessRequestAction::AttachInternal,
        };
        let case_id = self
            .authorize_case(
                &context,
                &request.organization_id,
                &request.case_ref,
                request.message_id.as_deref(),
                &authorized.subject,
                action,
            )
            .await
            .map_err(map_upload_case_authorization)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let request_hash = hash_request(&request).map_err(PluginError::runtime)?;
        let admission = storage::admit_attach(
            &prepared.postgres,
            &authorized.caller,
            attachment::UPLOAD_AND_ATTACH_OPERATION,
            &request.idempotency_key,
            &request_hash,
        )
        .await
        .map_err(map_upload_storage)?;
        let mut pending = match admission {
            Admission::Replay {
                receipt_id,
                attachment,
            } => {
                return Ok(UploadAndAttachResponse {
                    attachment: contract_attachment(*attachment).map_err(PluginError::runtime)?,
                    receipt_id,
                    replayed: true,
                });
            }
            Admission::Pending(pending) => pending,
        };

        let receipt_id = pending.receipt_id.hyphenated().to_string();
        let content_bytes = request.content.as_slice();
        let expected_sha256 = format!("{:x}", Sha256::digest(content_bytes));
        let expected_size_bytes = i64::try_from(content_bytes.len())
            .map_err(|_| PluginError::domain(UploadAndAttachError::InvalidRequest))?;
        let content_type = upload_content_type(&request.content_type);
        let grant = OwnerGrant {
            actor_id: authorized.subject.clone(),
            correlation_id: context.request_id().to_string(),
            owner: Owner {
                plugin_instance: prepared.instance_key.clone(),
                resource_id: receipt_id.clone(),
                resource_type: "support_attachment_upload".to_owned(),
                revision_id: Some(None),
            },
            tenant_id: request.organization_id.clone(),
        };
        let descriptor = loop {
            match upload_owned_content(
                &self.content_vault,
                &context,
                grant.clone(),
                &pending,
                UploadPayload {
                    bytes: content_bytes,
                    media_type: content_type,
                    sha256: &expected_sha256,
                    size_bytes: expected_size_bytes,
                },
            )
            .await
            {
                Ok(descriptor) => break descriptor,
                Err(UploadWorkflowFailure::Expired) => {
                    pending = storage::advance_upload_attempt(
                        &prepared.postgres,
                        &authorized.caller,
                        attachment::UPLOAD_AND_ATTACH_OPERATION,
                        &request.idempotency_key,
                        &request_hash,
                        &pending,
                    )
                    .await
                    .map_err(|error| storage_runtime(&error))?;
                }
                Err(UploadWorkflowFailure::Rejected) => {
                    return Err(PluginError::domain(UploadAndAttachError::ContentRejected));
                }
                Err(UploadWorkflowFailure::Runtime(error)) => {
                    return Err(PluginError::runtime(error));
                }
            }
        };
        if descriptor.sha256 != expected_sha256
            || descriptor.size_bytes != expected_size_bytes
            || descriptor.media_type != content_type
        {
            return Err(PluginError::runtime(RuntimeFailure::PluginFailure {
                detail: "Content Vault committed content that differs from the reservation"
                    .to_owned(),
            }));
        }
        let claim = self
            .content_vault
            .claim_with_context(
                context,
                ClaimRequest {
                    content_id: descriptor.content_id.clone(),
                    grant,
                    role: "support_attachment".to_owned(),
                    target: Owner {
                        plugin_instance: prepared.instance_key.clone(),
                        resource_id: pending.attachment_id.hyphenated().to_string(),
                        resource_type: "support_attachment".to_owned(),
                        revision_id: Some(None),
                    },
                },
            )
            .await
            .map_err(map_upload_claim_failure)?;
        if !claim.active {
            return Err(PluginError::runtime(RuntimeFailure::PluginFailure {
                detail: "Content Vault returned an inactive uploaded attachment claim".to_owned(),
            }));
        }
        let content_id = Uuid::parse_str(&descriptor.content_id)
            .map_err(|_| invalid_upload_vault_descriptor("content id"))?;
        let content_created_at = OffsetDateTime::parse(&descriptor.created_at, &Rfc3339)
            .map_err(|_| invalid_upload_vault_descriptor("creation timestamp"))?;
        let message_id = request
            .message_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| PluginError::domain(UploadAndAttachError::InvalidRequest))?;
        let visibility = visibility(&request.visibility);
        let (receipt_id, record, replayed) = storage::finish_attach(
            &prepared.postgres,
            &authorized.caller,
            attachment::UPLOAD_AND_ATTACH_OPERATION,
            &request.idempotency_key,
            &request_hash,
            &pending,
            &NewAttachment {
                organization_id: &request.organization_id,
                case_id,
                message_id,
                content_id,
                source_resource_type: "support_attachment_upload",
                source_resource_id: &receipt_id,
                source_revision_id: None,
                filename: &request.filename,
                media_type: content_type,
                visibility,
                sha256: &descriptor.sha256,
                size_bytes: descriptor.size_bytes,
                content_created_at,
                attached_by_subject: &authorized.subject,
            },
        )
        .await
        .map_err(map_upload_storage)?;
        Ok(UploadAndAttachResponse {
            attachment: contract_attachment(record).map_err(PluginError::runtime)?,
            receipt_id,
            replayed,
        })
    }

    async fn list_attachments(
        &self,
        context: Ctx,
        request: ListAttachmentsRequest,
    ) -> PluginResult<ListAttachmentsResponse, ListAttachmentsError> {
        let authorized = self
            .authenticate(&context, attachment::LIST_ATTACHMENTS_OPERATION)
            .map_err(map_list_authentication)?;
        let message_id = parse_optional_uuid(request.message_id.as_deref())
            .map_err(|()| PluginError::domain(ListAttachmentsError::InvalidRequest))?;
        let cursor = parse_optional_uuid(request.cursor.as_deref())
            .map_err(|()| PluginError::domain(ListAttachmentsError::InvalidRequest))?;
        if !valid_bounded(&request.organization_id, MAX_ORGANIZATION_CHARS)
            || !valid_bounded(&request.case_ref, MAX_CASE_REF_CHARS)
            || !(1..=200).contains(&request.limit)
        {
            return Err(PluginError::domain(ListAttachmentsError::InvalidRequest));
        }
        let case_id = self
            .authorize_case(
                &context,
                &request.organization_id,
                &request.case_ref,
                request.message_id.as_deref(),
                &authorized.subject,
                AuthorizeCaseAccessRequestAction::ReadPublic,
            )
            .await
            .map_err(map_list_case_authorization)?;
        let include_internal = match self
            .authorize_case(
                &context,
                &request.organization_id,
                &request.case_ref,
                request.message_id.as_deref(),
                &authorized.subject,
                AuthorizeCaseAccessRequestAction::ReadInternal,
            )
            .await
        {
            Ok(internal_case_id) if internal_case_id == case_id => true,
            Ok(_) => {
                return Err(PluginError::runtime(RuntimeFailure::PluginFailure {
                    detail: "Support Case Authorization returned inconsistent case ids".to_owned(),
                }));
            }
            Err(CaseAuthorizationFailure::Forbidden) => false,
            Err(CaseAuthorizationFailure::Runtime(error)) => {
                return Err(PluginError::runtime(error));
            }
        };
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let mut records = storage::list_attachments(
            &prepared.postgres,
            &request.organization_id,
            case_id,
            message_id,
            cursor,
            include_internal,
            request.limit + 1,
        )
        .await
        .map_err(|error| storage_runtime(&error))?;
        let page_size = usize::try_from(request.limit)
            .map_err(|_| PluginError::domain(ListAttachmentsError::InvalidRequest))?;
        let has_more = records.len() > page_size;
        if has_more {
            records.pop();
        }
        let next_cursor = has_more
            .then(|| records.last().map(|record| record.attachment_id.clone()))
            .flatten();
        let attachments = records
            .into_iter()
            .map(contract_attachment)
            .collect::<Result<Vec<_>, _>>()
            .map_err(PluginError::runtime)?;
        Ok(ListAttachmentsResponse {
            attachments,
            next_cursor,
        })
    }

    async fn get_attachment(
        &self,
        context: Ctx,
        request: GetAttachmentRequest,
    ) -> PluginResult<GetAttachmentResponse, GetAttachmentError> {
        let authorized = self
            .authenticate(&context, attachment::GET_ATTACHMENT_OPERATION)
            .map_err(map_get_authentication)?;
        let attachment_id = Uuid::parse_str(&request.attachment_id)
            .map_err(|_| PluginError::domain(GetAttachmentError::InvalidRequest))?;
        if !valid_bounded(&request.organization_id, MAX_ORGANIZATION_CHARS)
            || !valid_bounded(&request.case_ref, MAX_CASE_REF_CHARS)
        {
            return Err(PluginError::domain(GetAttachmentError::InvalidRequest));
        }
        let case_id = self
            .authorize_case(
                &context,
                &request.organization_id,
                &request.case_ref,
                None,
                &authorized.subject,
                AuthorizeCaseAccessRequestAction::ReadPublic,
            )
            .await
            .map_err(map_get_case_authorization)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let record = storage::get_attachment(
            &prepared.postgres,
            &request.organization_id,
            case_id,
            attachment_id,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .ok_or_else(|| PluginError::domain(GetAttachmentError::AttachmentNotFound))?;
        if record.visibility == "internal" {
            let internal_case_id = match self
                .authorize_case(
                    &context,
                    &request.organization_id,
                    &request.case_ref,
                    record.message_id.as_deref(),
                    &authorized.subject,
                    AuthorizeCaseAccessRequestAction::ReadInternal,
                )
                .await
            {
                Ok(case_id) => case_id,
                Err(CaseAuthorizationFailure::Forbidden) => {
                    return Err(PluginError::domain(GetAttachmentError::AttachmentNotFound));
                }
                Err(CaseAuthorizationFailure::Runtime(error)) => {
                    return Err(PluginError::runtime(error));
                }
            };
            if internal_case_id != case_id {
                return Err(PluginError::runtime(RuntimeFailure::PluginFailure {
                    detail: "Support Case Authorization returned inconsistent case ids".to_owned(),
                }));
            }
        }
        Ok(GetAttachmentResponse {
            attachment: contract_attachment(record).map_err(PluginError::runtime)?,
        })
    }
}

impl Lifecycle for PostgresSupportAttachmentPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared
            .borrow_mut()
            .replace(PreparedSupportAttachment {
                postgres,
                instance_key: context.instance_key().to_owned(),
            });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct AuthorizedCaller {
    caller: String,
    subject: String,
}

#[derive(Clone, Debug)]
struct SupportAttachmentActor {
    subject: String,
}

impl TypedActor for SupportAttachmentActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UtcClock;

impl AssertionClock for UtcClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Debug)]
enum AuthenticationFailure {
    Unauthenticated,
    Forbidden,
    Runtime(RuntimeFailure),
}

#[derive(Debug)]
enum CaseAuthorizationFailure {
    Forbidden,
    Runtime(RuntimeFailure),
}

#[derive(Debug)]
enum UploadWorkflowFailure {
    Expired,
    Rejected,
    Runtime(RuntimeFailure),
}

#[derive(Clone, Copy, Debug)]
struct UploadPayload<'a> {
    bytes: &'a [u8],
    media_type: &'a str,
    sha256: &'a str,
    size_bytes: i64,
}

async fn upload_owned_content(
    content_vault: &vault::ContentVaultClient,
    invocation: &Ctx,
    grant: OwnerGrant,
    pending: &storage::PendingReceipt,
    payload: UploadPayload<'_>,
) -> Result<ContentDescriptor, UploadWorkflowFailure> {
    let idempotency_key = format!(
        "support-attachment:{}:{}",
        pending.receipt_id.hyphenated(),
        pending.upload_attempt
    );
    let reservation = content_vault
        .reserve_with_context(
            invocation.clone(),
            ReserveRequest {
                expected_sha256: payload.sha256.to_owned(),
                expected_size_bytes: payload.size_bytes,
                grant: grant.clone(),
                idempotency_key,
                media_type: payload.media_type.to_owned(),
                ttl_seconds: UPLOAD_RESERVATION_TTL_SECONDS,
            },
        )
        .await
        .map_err(map_reserve_workflow_failure)?;
    if reservation.expected_sha256 != payload.sha256
        || reservation.expected_size_bytes != payload.size_bytes
        || reservation.media_type != payload.media_type
    {
        return Err(UploadWorkflowFailure::Runtime(
            RuntimeFailure::PluginFailure {
                detail: "Content Vault replayed a mismatched upload reservation".to_owned(),
            },
        ));
    }
    let next_offset = usize::try_from(reservation.next_offset).map_err(|_| {
        UploadWorkflowFailure::Runtime(RuntimeFailure::PluginFailure {
            detail: "Content Vault returned an invalid upload offset".to_owned(),
        })
    })?;
    if next_offset > payload.bytes.len() {
        return Err(UploadWorkflowFailure::Runtime(
            RuntimeFailure::PluginFailure {
                detail: "Content Vault returned an upload offset beyond the content".to_owned(),
            },
        ));
    }
    let stream = content_vault
        .upload_with_context(
            invocation.clone(),
            UploadRequest {
                grant,
                session_id: reservation.session_id,
            },
        )
        .await
        .map_err(map_upload_open_workflow_failure)?;
    if next_offset < payload.bytes.len() {
        stream
            .send(UploadFrame {
                bytes_base64: Some(Some(STANDARD.encode(&payload.bytes[next_offset..]))),
                content: None,
                kind: UploadFrameKind::Chunk,
                offset: Some(i64::try_from(next_offset).map_err(|_| {
                    UploadWorkflowFailure::Runtime(RuntimeFailure::PluginFailure {
                        detail: "Support Attachment upload offset exceeded i64".to_owned(),
                    })
                })?),
            })
            .await
            .map_err(UploadWorkflowFailure::Runtime)?;
    }
    stream
        .close_send()
        .await
        .map_err(UploadWorkflowFailure::Runtime)?;

    receive_committed_upload(stream, payload.size_bytes).await
}

async fn receive_committed_upload(
    stream: lenso_kernel::NativeStream<vault::ContentVaultUpload>,
    expected_size_bytes: i64,
) -> Result<ContentDescriptor, UploadWorkflowFailure> {
    let mut committed = None;
    loop {
        match stream
            .receive()
            .await
            .map_err(UploadWorkflowFailure::Runtime)?
        {
            StreamEvent::Message(frame) => {
                if frame.kind != UploadFrameKind::Committed
                    || frame.bytes_base64.flatten().is_some()
                    || frame.offset != Some(expected_size_bytes)
                    || committed.is_some()
                {
                    return Err(UploadWorkflowFailure::Runtime(
                        RuntimeFailure::ProtocolViolation {
                            capability: vault::CAPABILITY_ID,
                        },
                    ));
                }
                committed = frame.content.flatten();
                if committed.is_none() {
                    return Err(UploadWorkflowFailure::Runtime(
                        RuntimeFailure::ProtocolViolation {
                            capability: vault::CAPABILITY_ID,
                        },
                    ));
                }
            }
            StreamEvent::PeerHalfClosed => {}
            StreamEvent::Terminal(Ok(())) => {
                return committed.ok_or({
                    UploadWorkflowFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: vault::CAPABILITY_ID,
                    })
                });
            }
            StreamEvent::Terminal(Err(error)) => {
                return Err(map_upload_domain_workflow_failure(&error));
            }
        }
    }
}

fn map_reserve_workflow_failure(
    error: ContentVaultReserveInvocationError,
) -> UploadWorkflowFailure {
    match error {
        ContentVaultReserveInvocationError::Domain(ReserveError::UploadExpired) => {
            UploadWorkflowFailure::Expired
        }
        ContentVaultReserveInvocationError::Domain(ReserveError::UploadRejected) => {
            UploadWorkflowFailure::Rejected
        }
        ContentVaultReserveInvocationError::Domain(_) => content_vault_upload_runtime("reserve"),
        ContentVaultReserveInvocationError::Runtime(error) => UploadWorkflowFailure::Runtime(error),
    }
}

fn map_upload_open_workflow_failure(
    error: ContentVaultUploadInvocationError,
) -> UploadWorkflowFailure {
    match error {
        ContentVaultUploadInvocationError::Domain(error) => {
            map_upload_domain_workflow_failure(&error)
        }
        ContentVaultUploadInvocationError::Runtime(error) => UploadWorkflowFailure::Runtime(error),
    }
}

fn map_upload_domain_workflow_failure(error: &UploadError) -> UploadWorkflowFailure {
    match error {
        UploadError::UploadExpired => UploadWorkflowFailure::Expired,
        UploadError::UploadRejected => UploadWorkflowFailure::Rejected,
        _ => content_vault_upload_runtime("upload"),
    }
}

fn content_vault_upload_runtime(operation: &str) -> UploadWorkflowFailure {
    UploadWorkflowFailure::Runtime(RuntimeFailure::PluginFailure {
        detail: format!("Content Vault rejected Support Attachment {operation}"),
    })
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("database URL secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

fn map_attach_authentication(failure: AuthenticationFailure) -> PluginError<AttachContentError> {
    match failure {
        AuthenticationFailure::Unauthenticated => {
            PluginError::domain(AttachContentError::Unauthenticated)
        }
        AuthenticationFailure::Forbidden => PluginError::domain(AttachContentError::Forbidden),
        AuthenticationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_upload_authentication(failure: AuthenticationFailure) -> PluginError<UploadAndAttachError> {
    match failure {
        AuthenticationFailure::Unauthenticated => {
            PluginError::domain(UploadAndAttachError::Unauthenticated)
        }
        AuthenticationFailure::Forbidden => PluginError::domain(UploadAndAttachError::Forbidden),
        AuthenticationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_list_authentication(failure: AuthenticationFailure) -> PluginError<ListAttachmentsError> {
    match failure {
        AuthenticationFailure::Unauthenticated => {
            PluginError::domain(ListAttachmentsError::Unauthenticated)
        }
        AuthenticationFailure::Forbidden => PluginError::domain(ListAttachmentsError::Forbidden),
        AuthenticationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_get_authentication(failure: AuthenticationFailure) -> PluginError<GetAttachmentError> {
    match failure {
        AuthenticationFailure::Unauthenticated => {
            PluginError::domain(GetAttachmentError::Unauthenticated)
        }
        AuthenticationFailure::Forbidden => PluginError::domain(GetAttachmentError::Forbidden),
        AuthenticationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_attach_case_authorization(
    failure: CaseAuthorizationFailure,
) -> PluginError<AttachContentError> {
    match failure {
        CaseAuthorizationFailure::Forbidden => PluginError::domain(AttachContentError::Forbidden),
        CaseAuthorizationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_upload_case_authorization(
    failure: CaseAuthorizationFailure,
) -> PluginError<UploadAndAttachError> {
    match failure {
        CaseAuthorizationFailure::Forbidden => PluginError::domain(UploadAndAttachError::Forbidden),
        CaseAuthorizationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_list_case_authorization(
    failure: CaseAuthorizationFailure,
) -> PluginError<ListAttachmentsError> {
    match failure {
        CaseAuthorizationFailure::Forbidden => PluginError::domain(ListAttachmentsError::Forbidden),
        CaseAuthorizationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_get_case_authorization(
    failure: CaseAuthorizationFailure,
) -> PluginError<GetAttachmentError> {
    match failure {
        CaseAuthorizationFailure::Forbidden => PluginError::domain(GetAttachmentError::Forbidden),
        CaseAuthorizationFailure::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_describe_failure(
    error: ContentVaultDescribeInvocationError,
) -> PluginError<AttachContentError> {
    match error {
        ContentVaultDescribeInvocationError::Domain(DescribeError::NotFound) => {
            PluginError::domain(AttachContentError::ContentNotFound)
        }
        ContentVaultDescribeInvocationError::Domain(
            DescribeError::IntegrityMismatch | DescribeError::IntegrityMissing,
        ) => PluginError::domain(AttachContentError::ContentMismatch),
        ContentVaultDescribeInvocationError::Domain(_) => {
            PluginError::domain(AttachContentError::InvalidRequest)
        }
        ContentVaultDescribeInvocationError::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_claim_failure(error: ContentVaultClaimInvocationError) -> PluginError<AttachContentError> {
    match error {
        ContentVaultClaimInvocationError::Domain(ClaimError::NotFound) => {
            PluginError::domain(AttachContentError::ContentNotFound)
        }
        ContentVaultClaimInvocationError::Domain(
            ClaimError::IntegrityMismatch | ClaimError::IntegrityMissing,
        ) => PluginError::domain(AttachContentError::ContentMismatch),
        ContentVaultClaimInvocationError::Domain(_) => {
            PluginError::domain(AttachContentError::InvalidRequest)
        }
        ContentVaultClaimInvocationError::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_upload_claim_failure(
    error: ContentVaultClaimInvocationError,
) -> PluginError<UploadAndAttachError> {
    match error {
        ContentVaultClaimInvocationError::Domain(
            ClaimError::UploadRejected
            | ClaimError::IntegrityMismatch
            | ClaimError::IntegrityMissing,
        ) => PluginError::domain(UploadAndAttachError::ContentRejected),
        ContentVaultClaimInvocationError::Domain(_) => {
            PluginError::runtime(RuntimeFailure::PluginFailure {
                detail: "Content Vault rejected the uploaded attachment claim".to_owned(),
            })
        }
        ContentVaultClaimInvocationError::Runtime(error) => PluginError::runtime(error),
    }
}

fn map_attach_storage(error: StorageError) -> PluginError<AttachContentError> {
    match error {
        StorageError::Domain(DomainFailure::IdempotencyConflict) => {
            PluginError::domain(AttachContentError::IdempotencyConflict)
        }
        other => storage_runtime(&other),
    }
}

fn map_upload_storage(error: StorageError) -> PluginError<UploadAndAttachError> {
    match error {
        StorageError::Domain(DomainFailure::IdempotencyConflict) => {
            PluginError::domain(UploadAndAttachError::IdempotencyConflict)
        }
        other => storage_runtime(&other),
    }
}

fn storage_runtime<E>(error: &StorageError) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    })
}

fn hash_request(request: &impl Serialize) -> Result<Vec<u8>, RuntimeFailure> {
    serde_json::to_vec(request)
        .map(|wire| Sha256::digest(wire).to_vec())
        .map_err(|error| RuntimeFailure::Internal {
            detail: format!("Support Attachment request serialization failed: {error}"),
        })
}

fn contract_attachment(record: storage::AttachmentRecord) -> Result<Attachment, RuntimeFailure> {
    let media_type = match record.media_type.as_str() {
        "image/png" => AttachmentMediaType::ImagePng,
        "image/jpeg" => AttachmentMediaType::ImageJpeg,
        "text/plain" => AttachmentMediaType::TextPlain,
        _ => return Err(invalid_storage_value("media type")),
    };
    let visibility = match record.visibility.as_str() {
        "public" => AttachmentVisibility::Public,
        "internal" => AttachmentVisibility::Internal,
        _ => return Err(invalid_storage_value("visibility")),
    };
    Ok(Attachment {
        attached_by_subject: record.attached_by_subject,
        attachment_id: record.attachment_id,
        case_id: record.case_id,
        content_created_at: record.content_created_at,
        content_id: record.content_id,
        created_at: record.created_at,
        filename: record.filename,
        media_type,
        message_id: record.message_id,
        organization_id: record.organization_id,
        sha256: record.sha256,
        size_bytes: record.size_bytes,
        visibility,
    })
}

fn invalid_storage_value(field: &str) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: format!("Support Attachment stored an invalid {field}"),
    }
}

fn invalid_vault_descriptor(field: &str) -> PluginError<AttachContentError> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: format!("Content Vault returned an invalid {field}"),
    })
}

fn invalid_upload_vault_descriptor(field: &str) -> PluginError<UploadAndAttachError> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: format!("Content Vault returned an invalid {field}"),
    })
}

fn validate_attach_request(request: &AttachContentRequest) -> bool {
    valid_bounded(&request.organization_id, MAX_ORGANIZATION_CHARS)
        && valid_bounded(&request.case_ref, MAX_CASE_REF_CHARS)
        && request
            .message_id
            .as_deref()
            .is_none_or(|value| Uuid::parse_str(value).is_ok())
        && valid_bounded(&request.source.resource_type, MAX_OWNER_TYPE_CHARS)
        && valid_bounded(&request.source.resource_id, MAX_OWNER_ID_CHARS)
        && request
            .source
            .revision_id
            .as_deref()
            .is_none_or(|value| valid_bounded(value, MAX_OWNER_ID_CHARS))
        && Uuid::parse_str(&request.content_id).is_ok()
        && valid_filename(&request.filename)
        && valid_bounded(&request.idempotency_key, MAX_IDEMPOTENCY_CHARS)
}

fn validate_upload_and_attach_request(request: &UploadAndAttachRequest) -> bool {
    valid_bounded(&request.organization_id, MAX_ORGANIZATION_CHARS)
        && valid_bounded(&request.case_ref, MAX_CASE_REF_CHARS)
        && request
            .message_id
            .as_deref()
            .is_none_or(|value| Uuid::parse_str(value).is_ok())
        && valid_filename(&request.filename)
        && (1..=MAX_INLINE_UPLOAD_BYTES).contains(&request.content.len())
        && valid_bounded(&request.idempotency_key, MAX_IDEMPOTENCY_CHARS)
}

fn media_type(value: &MediaType) -> &'static str {
    match value {
        MediaType::ImagePng => "image/png",
        MediaType::ImageJpeg => "image/jpeg",
        MediaType::TextPlain => "text/plain",
    }
}

fn upload_content_type(value: &UploadContentType) -> &'static str {
    match value {
        UploadContentType::TextPlain => "text/plain",
    }
}

fn visibility(value: &Visibility) -> &'static str {
    match value {
        Visibility::Public => "public",
        Visibility::Internal => "internal",
    }
}

fn parse_optional_uuid(value: Option<&str>) -> Result<Option<Uuid>, ()> {
    value.map(Uuid::parse_str).transpose().map_err(|_| ())
}

fn valid_filename(value: &str) -> bool {
    valid_bounded(value, MAX_FILENAME_CHARS)
        && !value
            .chars()
            .any(|character| matches!(character, '/' | '\\'))
}

fn valid_bounded(value: &str, maximum_characters: usize) -> bool {
    let mut count = 0_usize;
    let mut visible = false;
    for character in value.chars() {
        count += 1;
        if character.is_control() {
            return false;
        }
        visible |= !character.is_whitespace();
    }
    visible && count <= maximum_characters
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-' | b':' | b'/'))
        })
}

fn valid_secret_reference(reference: &str) -> bool {
    valid_identifier(reference, 256)
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

fn validate_callers(callers: &[String]) -> Result<(), ()> {
    if callers.is_empty()
        || callers.len() > MAX_CALLERS
        || callers.iter().any(|caller| !valid_identifier(caller, 200))
        || callers.iter().collect::<BTreeSet<_>>().len() != callers.len()
    {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_auth_sdk::ActorAssertionIssuer;
    use lenso_native_adapter::NativePluginRegistry;

    fn config() -> SupportAttachmentConfig {
        let issuer = ActorAssertionIssuer::new("auth.users", b"support-attachment-test-key");
        SupportAttachmentConfig::new(
            "support_attachment",
            "support-attachment/database-url",
            "auth.users",
            issuer.public_key_base64(),
            vec!["support-web".to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn descriptor_has_only_the_explicit_collaboration_edges() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let provided_capabilities = descriptor["provided_capabilities"].as_array().unwrap();
        let provided = provided_capabilities
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(provided, BTreeSet::from([attachment::CAPABILITY_ID]));
        assert!(
            provided_capabilities[0]["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|operation| {
                    operation.as_str() == Some(attachment::UPLOAD_AND_ATTACH_OPERATION)
                })
        );
        let required = descriptor["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            required,
            BTreeSet::from([
                secrets::CAPABILITY_ID,
                vault::CAPABILITY_ID,
                case_authorization::CAPABILITY_ID,
            ])
        );
        assert_eq!(
            NativePluginRegistry::new()
                .with_linked_factories()
                .factories()
                .filter(|factory| factory.package_id() == PACKAGE_ID)
                .count(),
            1
        );
    }

    #[test]
    fn configuration_rejects_duplicate_callers_and_path_traversal() {
        let mut invalid = config();
        invalid.business_callers.push("support-web".to_owned());
        assert_eq!(
            invalid.validate(),
            Err(SupportAttachmentConfigError::InvalidBusinessCallers)
        );
        invalid = config();
        invalid.database_url_secret = "../database".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(SupportAttachmentConfigError::InvalidSecretReference)
        );
        invalid = config();
        invalid.auth_assertion_public_key = "A".repeat(4097);
        assert_eq!(
            invalid.validate(),
            Err(SupportAttachmentConfigError::InvalidAuthPublicKey)
        );
    }

    #[test]
    fn filenames_are_basenames_and_visibility_actions_are_explicit() {
        assert!(valid_filename("customer-log.txt"));
        assert!(!valid_filename("../customer-log.txt"));
        assert!(!valid_filename("folder/log.txt"));
        assert!(matches!(
            AuthorizeCaseAccessRequestAction::AttachInternal,
            AuthorizeCaseAccessRequestAction::AttachInternal
        ));
    }

    #[test]
    fn inline_upload_validation_enforces_the_raw_byte_boundary() {
        let request = |content| UploadAndAttachRequest {
            case_ref: "CASE-42".to_owned(),
            content,
            content_type: UploadContentType::TextPlain,
            filename: "diagnostic.txt".to_owned(),
            idempotency_key: "upload-42".to_owned(),
            message_id: None,
            organization_id: "org-1".to_owned(),
            visibility: Visibility::Internal,
        };

        assert!(validate_upload_and_attach_request(&request(
            vec![b'a'; MAX_INLINE_UPLOAD_BYTES].into()
        )));
        assert!(!validate_upload_and_attach_request(&request(
            Vec::<u8>::new().into()
        )));
        assert!(!validate_upload_and_attach_request(&request(
            vec![b'a'; MAX_INLINE_UPLOAD_BYTES + 1].into()
        )));
    }
}
