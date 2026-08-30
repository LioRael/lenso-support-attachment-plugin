use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![(
    1,
    "create-support-attachments",
    "migrations/001_create_support_attachments.sql",
)];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_name_is_validated_by_postgres_kit() {
        assert!(schema_plan("support_attachment").is_ok());
        assert!(schema_plan("not-valid").is_err());
    }
}
