//! Generated Support Attachment Capability contract.

include!("generated.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_upload_schema_and_debug_keep_content_bounded_and_sensitive() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../schemas/upload-and-attach-request.schema.json"
        ))
        .unwrap();
        let content = &schema["properties"]["content"];
        assert_eq!(content["format"], "byte");
        assert_eq!(content["minLength"], 4);
        assert_eq!(content["maxLength"], 11_184_812);
        assert_eq!(content["x-lenso-sensitive"], true);

        let request = UploadAndAttachRequest {
            case_ref: "CASE-42".to_owned(),
            content: Bytes::from(b"private diagnostic".as_slice()),
            content_type: UploadContentType::TextPlain,
            filename: "diagnostic.txt".to_owned(),
            idempotency_key: "upload-42".to_owned(),
            message_id: None,
            organization_id: "org-1".to_owned(),
            visibility: Visibility::Internal,
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("private diagnostic"));
    }
}
