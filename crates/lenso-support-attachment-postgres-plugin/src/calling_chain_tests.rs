use std::{cell::RefCell, rc::Rc, time::Duration};

use futures::future::LocalBoxFuture;
use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_kernel::{
    InvocationContext, Kernel, NativeRequestEndpoint, NativeRequestFuture, NativeStreamSession,
    NoopPluginLifecycle, PluginLifecycle, PrepareContext, RuntimeFailure, ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_runner::TokioDriver;

use super::*;

const CALLER_PACKAGE: &str = "test.support-attachment-caller";
const CONSUMER_PACKAGE: &str = "test.support-attachment-upload-consumer";
const VAULT_PACKAGE: &str = "test.support-attachment-content-vault";
const CONTENT_ID: &str = "018f0000-0000-7000-8000-000000000001";
const SESSION_ID: &str = "018f0000-0000-7000-8000-000000000002";
const RECEIPT_ID: &str = "018f0000-0000-7000-8000-000000000003";
const ATTACHMENT_ID: &str = "018f0000-0000-7000-8000-000000000004";

#[derive(Debug, Default)]
struct VaultObservation {
    expected_sha256: String,
    expected_size_bytes: i64,
    media_type: String,
    uploaded: Vec<u8>,
    claim_seen: bool,
}

#[tokio::test(flavor = "current_thread")]
async fn generated_port_uploads_and_claims_with_the_attachment_instance_identity() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let observation = Rc::new(RefCell::new(VaultObservation::default()));
            let app = Kernel::start_native(
                upload_chain_plan(),
                TokioDriver::new(),
                NativePluginRegistry::new()
                    .with_factory(EmptyFactory)
                    .with_factory(UploadConsumerFactory)
                    .with_factory(FakeVaultFactory {
                        observation: Rc::clone(&observation),
                    }),
            )
            .await
            .unwrap();

            let content = b"bounded support attachment".to_vec();
            let response = app
                .invoke::<attachment::SupportAttachmentUploadAndAttach>(
                    "caller",
                    attachment::UPLOAD_AND_ATTACH_OPERATION,
                    UploadAndAttachRequest {
                        case_ref: "CASE-42".to_owned(),
                        content: content.clone().into(),
                        content_type: UploadContentType::TextPlain,
                        filename: "diagnostic.txt".to_owned(),
                        idempotency_key: "upload-42".to_owned(),
                        message_id: None,
                        organization_id: "org-1".to_owned(),
                        visibility: Visibility::Internal,
                    },
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.attachment.content_id, CONTENT_ID);
            assert_eq!(
                response.attachment.size_bytes,
                i64::try_from(content.len()).unwrap()
            );

            {
                let observed = observation.borrow();
                assert_eq!(observed.uploaded, content);
                assert_eq!(observed.media_type, "text/plain");
                assert!(observed.claim_seen);
                assert_eq!(
                    observed.expected_sha256,
                    format!("{:x}", Sha256::digest(&observed.uploaded))
                );
            }
            assert_eq!(
                app.shutdown(Duration::from_secs(1)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

#[derive(Clone, Copy, Debug)]
struct EmptyFactory;

impl NativePluginFactory for EmptyFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

#[derive(Clone, Copy, Debug)]
struct UploadConsumerFactory;

impl NativePluginFactory for UploadConsumerFactory {
    fn package_id(&self) -> &'static str {
        CONSUMER_PACKAGE
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        let client = Rc::new(RefCell::new(None));
        Ok(NativePluginInstance::with_lifecycle(
            vec![Rc::new(UploadConsumerEndpoint {
                client: Rc::clone(&client),
            })],
            UploadConsumerLifecycle { client },
        ))
    }
}

#[derive(Debug)]
struct UploadConsumerLifecycle {
    client: Rc<RefCell<Option<vault::ContentVaultClient>>>,
}

impl PluginLifecycle for UploadConsumerLifecycle {
    fn prepare(&self, context: PrepareContext) -> lenso_kernel::PluginFuture {
        let result = vault::ContentVaultClient::from_dependencies(context.dependencies())
            .map(|client| self.client.borrow_mut().replace(client))
            .map(|_| ());
        Box::pin(std::future::ready(result))
    }
}

#[derive(Debug)]
struct UploadConsumerEndpoint {
    client: Rc<RefCell<Option<vault::ContentVaultClient>>>,
}

impl NativeRequestEndpoint for UploadConsumerEndpoint {
    fn capability_id(&self) -> &'static str {
        attachment::CAPABILITY_ID
    }

    fn descriptor_version(&self) -> &'static str {
        attachment::DESCRIPTOR_VERSION
    }

    fn operations(&self) -> &'static [&'static str] {
        &[attachment::UPLOAD_AND_ATTACH_OPERATION]
    }

    fn invoke(
        &self,
        operation: &str,
        request: Box<dyn std::any::Any>,
        context: InvocationContext,
    ) -> LocalBoxFuture<
        'static,
        Result<Result<Box<dyn std::any::Any>, Box<dyn std::any::Any>>, RuntimeFailure>,
    > {
        if operation != attachment::UPLOAD_AND_ATTACH_OPERATION {
            return Box::pin(std::future::ready(Err(RuntimeFailure::UnknownOperation {
                capability: attachment::CAPABILITY_ID,
                operation: operation.to_owned(),
            })));
        }
        let Ok(request) = request.downcast::<UploadAndAttachRequest>() else {
            return Box::pin(std::future::ready(Err(RuntimeFailure::ProtocolViolation {
                capability: attachment::CAPABILITY_ID,
            })));
        };
        let Some(client) = self.client.borrow_mut().take() else {
            return Box::pin(std::future::ready(Err(RuntimeFailure::PluginFailure {
                detail: "test upload consumer was not prepared".to_owned(),
            })));
        };
        Box::pin(async move {
            let expected_sha256 = format!("{:x}", Sha256::digest(request.content.as_slice()));
            let expected_size_bytes = i64::try_from(request.content.len()).unwrap();
            let receipt_id = Uuid::parse_str(RECEIPT_ID).unwrap();
            let attachment_id = Uuid::parse_str(ATTACHMENT_ID).unwrap();
            let pending = storage::PendingReceipt {
                receipt_id,
                attachment_id,
                upload_attempt: 0,
            };
            let grant = OwnerGrant {
                actor_id: "usr-1".to_owned(),
                correlation_id: context.request_id().to_string(),
                owner: Owner {
                    plugin_instance: "attachment".to_owned(),
                    resource_id: RECEIPT_ID.to_owned(),
                    resource_type: "support_attachment_upload".to_owned(),
                    revision_id: Some(None),
                },
                tenant_id: request.organization_id.clone(),
            };
            let descriptor = upload_owned_content(
                &client,
                &context,
                grant.clone(),
                &pending,
                UploadPayload {
                    bytes: request.content.as_slice(),
                    media_type: "text/plain",
                    sha256: &expected_sha256,
                    size_bytes: expected_size_bytes,
                },
            )
            .await
            .map_err(|failure| match failure {
                UploadWorkflowFailure::Runtime(error) => error,
                UploadWorkflowFailure::Expired | UploadWorkflowFailure::Rejected => {
                    RuntimeFailure::PluginFailure {
                        detail: "test Vault rejected valid content".to_owned(),
                    }
                }
            })?;
            client
                .claim_with_context(
                    context,
                    ClaimRequest {
                        content_id: descriptor.content_id.clone(),
                        grant,
                        role: "support_attachment".to_owned(),
                        target: Owner {
                            plugin_instance: "attachment".to_owned(),
                            resource_id: ATTACHMENT_ID.to_owned(),
                            resource_type: "support_attachment".to_owned(),
                            revision_id: Some(None),
                        },
                    },
                )
                .await
                .map_err(|_| RuntimeFailure::PluginFailure {
                    detail: "test Vault rejected the claim".to_owned(),
                })?;
            Ok(Ok(Box::new(UploadAndAttachResponse {
                attachment: Attachment {
                    attached_by_subject: "usr-1".to_owned(),
                    attachment_id: ATTACHMENT_ID.to_owned(),
                    case_id: "018f0000-0000-7000-8000-000000000005".to_owned(),
                    content_created_at: descriptor.created_at,
                    content_id: descriptor.content_id,
                    created_at: "2026-08-31T00:00:00Z".to_owned(),
                    filename: request.filename,
                    media_type: AttachmentMediaType::TextPlain,
                    message_id: None,
                    organization_id: request.organization_id,
                    sha256: descriptor.sha256,
                    size_bytes: descriptor.size_bytes,
                    visibility: AttachmentVisibility::Internal,
                },
                receipt_id: RECEIPT_ID.to_owned(),
                replayed: false,
            }) as Box<dyn std::any::Any>))
        })
    }
}

#[derive(Clone, Debug)]
struct FakeVaultFactory {
    observation: Rc<RefCell<VaultObservation>>,
}

impl NativePluginFactory for FakeVaultFactory {
    fn package_id(&self) -> &'static str {
        VAULT_PACKAGE
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        let endpoint = Rc::new(vault::ContentVaultEndpoint::new(FakeVault {
            observation: Rc::clone(&self.observation),
        }));
        Ok(NativePluginInstance::with_endpoints(
            vec![endpoint.clone()],
            vec![endpoint],
            NoopPluginLifecycle,
        ))
    }
}

#[derive(Clone, Debug)]
struct FakeVault {
    observation: Rc<RefCell<VaultObservation>>,
}

impl vault::ContentVaultProvider for FakeVault {
    fn claim(
        &self,
        context: InvocationContext,
        request: ClaimRequest,
    ) -> NativeRequestFuture<vault::ContentVaultClaim> {
        let observation = Rc::clone(&self.observation);
        Box::pin(std::future::ready(
            if context.caller_instance() != Some("attachment")
                || request.grant.owner.plugin_instance != "attachment"
                || request.target.plugin_instance != "attachment"
                || request.content_id != CONTENT_ID
                || request.target.resource_id != ATTACHMENT_ID
            {
                Ok(Err(ClaimError::Unauthorized))
            } else {
                observation.borrow_mut().claim_seen = true;
                Ok(Ok(vault::ClaimResponse { active: true }))
            },
        ))
    }

    fn describe(
        &self,
        _: InvocationContext,
        _: DescribeRequest,
    ) -> NativeRequestFuture<vault::ContentVaultDescribe> {
        unsupported_request::<vault::ContentVaultDescribe>(vault::DESCRIBE_OPERATION)
    }

    fn download(
        &self,
        _: InvocationContext,
        _: vault::DownloadRequest,
    ) -> LocalBoxFuture<
        'static,
        Result<Box<dyn NativeStreamSession>, vault::ContentVaultDownloadInvocationError>,
    > {
        Box::pin(std::future::ready(Err(
            vault::ContentVaultDownloadInvocationError::Runtime(RuntimeFailure::UnknownOperation {
                capability: vault::CAPABILITY_ID,
                operation: vault::DOWNLOAD_OPERATION.to_owned(),
            }),
        )))
    }

    fn release_claim(
        &self,
        _: InvocationContext,
        _: vault::ReleaseClaimRequest,
    ) -> NativeRequestFuture<vault::ContentVaultReleaseClaim> {
        unsupported_request::<vault::ContentVaultReleaseClaim>(vault::RELEASE_CLAIM_OPERATION)
    }

    fn reserve(
        &self,
        context: InvocationContext,
        request: ReserveRequest,
    ) -> NativeRequestFuture<vault::ContentVaultReserve> {
        let valid_owner = context.caller_instance() == Some("attachment")
            && request.grant.owner.plugin_instance == "attachment"
            && request.grant.owner.resource_type == "support_attachment_upload"
            && request.grant.owner.resource_id == RECEIPT_ID;
        if !valid_owner {
            return Box::pin(std::future::ready(Ok(Err(ReserveError::Unauthorized))));
        }
        let mut observation = self.observation.borrow_mut();
        observation.expected_sha256 = request.expected_sha256.clone();
        observation.expected_size_bytes = request.expected_size_bytes;
        observation.media_type = request.media_type.clone();
        Box::pin(std::future::ready(Ok(Ok(vault::ReserveResponse {
            expected_sha256: request.expected_sha256,
            expected_size_bytes: request.expected_size_bytes,
            expires_at: "2026-09-01T00:00:00Z".to_owned(),
            media_type: request.media_type,
            next_offset: 0,
            session_id: SESSION_ID.to_owned(),
            state: vault::UploadState::Reserved,
        }))))
    }

    fn sweep(
        &self,
        _: InvocationContext,
        _: vault::SweepRequest,
    ) -> NativeRequestFuture<vault::ContentVaultSweep> {
        unsupported_request::<vault::ContentVaultSweep>(vault::SWEEP_OPERATION)
    }

    fn upload(
        &self,
        context: InvocationContext,
        request: UploadRequest,
    ) -> LocalBoxFuture<
        'static,
        Result<Box<dyn NativeStreamSession>, ContentVaultUploadInvocationError>,
    > {
        if context.caller_instance() != Some("attachment")
            || request.grant.owner.plugin_instance != "attachment"
            || request.session_id != SESSION_ID
        {
            return Box::pin(std::future::ready(Err(
                ContentVaultUploadInvocationError::Domain(UploadError::Unauthorized),
            )));
        }
        let observation = Rc::clone(&self.observation);
        let (stream, mut channel) =
            ProviderStream::<vault::ContentVaultUpload>::channel(&context, 1);
        tokio::task::spawn_local(async move {
            let mut uploaded = Vec::new();
            while let StreamInput::Message(frame) = channel.receive().await.unwrap() {
                assert_eq!(frame.kind, UploadFrameKind::Chunk);
                assert_eq!(frame.offset, Some(i64::try_from(uploaded.len()).unwrap()));
                let encoded = frame.bytes_base64.flatten().unwrap();
                uploaded.extend(STANDARD.decode(encoded).unwrap());
            }
            let descriptor = {
                let observed = observation.borrow();
                assert_eq!(
                    i64::try_from(uploaded.len()).unwrap(),
                    observed.expected_size_bytes
                );
                assert_eq!(
                    format!("{:x}", Sha256::digest(&uploaded)),
                    observed.expected_sha256
                );
                ContentDescriptor {
                    content_id: CONTENT_ID.to_owned(),
                    created_at: "2026-08-31T00:00:00Z".to_owned(),
                    media_type: observed.media_type.clone(),
                    sha256: observed.expected_sha256.clone(),
                    size_bytes: observed.expected_size_bytes,
                }
            };
            let committed_offset = descriptor.size_bytes;
            observation.borrow_mut().uploaded = uploaded;
            channel
                .send(UploadFrame {
                    bytes_base64: None,
                    content: Some(Some(descriptor)),
                    kind: UploadFrameKind::Committed,
                    offset: Some(committed_offset),
                })
                .await
                .unwrap();
            channel.complete(Ok(())).await.unwrap();
        });
        Box::pin(std::future::ready(Ok(
            Box::new(stream) as Box<dyn NativeStreamSession>
        )))
    }
}

fn unsupported_request<C>(operation: &str) -> NativeRequestFuture<C>
where
    C: lenso_kernel::RequestCapability,
{
    Box::pin(std::future::ready(Err(RuntimeFailure::UnknownOperation {
        capability: vault::CAPABILITY_ID,
        operation: operation.to_owned(),
    })))
}

fn upload_chain_plan() -> ResolvedAppPlan {
    let caller = PluginInstancePlan::new("caller", CALLER_PACKAGE).with_requirement(
        CapabilityRequirementPlan::one(attachment::CAPABILITY_ID, attachment::DESCRIPTOR_VERSION),
    );
    let consumer = PluginInstancePlan::new("attachment", CONSUMER_PACKAGE)
        .with_capability(CapabilityEndpointPlan::new(
            attachment::CAPABILITY_ID,
            attachment::DESCRIPTOR_VERSION,
            [attachment::UPLOAD_AND_ATTACH_OPERATION],
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            vault::CAPABILITY_ID,
            vault::DESCRIPTOR_VERSION,
        ));
    let provider = PluginInstancePlan::new("vault", VAULT_PACKAGE).with_capability(
        CapabilityEndpointPlan::new(
            vault::CAPABILITY_ID,
            vault::DESCRIPTOR_VERSION,
            [
                vault::CLAIM_OPERATION,
                vault::DESCRIBE_OPERATION,
                vault::DOWNLOAD_OPERATION,
                vault::RELEASE_CLAIM_OPERATION,
                vault::RESERVE_OPERATION,
                vault::SWEEP_OPERATION,
                vault::UPLOAD_OPERATION,
            ],
        )
        .with_stream_operation(vault::DOWNLOAD_OPERATION)
        .with_stream_operation(vault::UPLOAD_OPERATION),
    );
    AppComposition::new(
        vec![caller, consumer, provider],
        vec![
            CapabilityBinding::new(
                "caller",
                attachment::CAPABILITY_ID,
                attachment::DESCRIPTOR_VERSION,
                "attachment",
            ),
            CapabilityBinding::new(
                "attachment",
                vault::CAPABILITY_ID,
                vault::DESCRIPTOR_VERSION,
                "vault",
            ),
        ],
    )
    .resolve()
    .unwrap()
}
