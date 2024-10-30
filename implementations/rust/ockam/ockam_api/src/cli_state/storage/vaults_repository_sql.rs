use std::path::PathBuf;

use sqlx::*;

use ockam::{FromSqlxError, SqlxDatabase, ToVoid};
use ockam_core::async_trait;
use ockam_core::errcode::{Kind, Origin};
use ockam_core::Result;
use ockam_node::database::{Boolean, Nullable};

use crate::cli_state::{NamedVault, UseAwsKms, VaultType, VaultsRepository};

#[derive(Clone)]
pub struct VaultsSqlxDatabase {
    database: SqlxDatabase,
}

impl VaultsSqlxDatabase {
    pub fn new(database: SqlxDatabase) -> Self {
        debug!("create a repository for vaults");
        Self { database }
    }

    /// Create a new in-memory database
    pub async fn create() -> Result<Self> {
        Ok(Self::new(SqlxDatabase::in_memory("vaults").await?))
    }
}

#[async_trait]
impl VaultsRepository for VaultsSqlxDatabase {
    async fn store_vault(&self, name: &str, vault_type: VaultType) -> Result<NamedVault> {
        let mut transaction = self.database.begin().await.into_core()?;

        let query1 =
            query_scalar("SELECT EXISTS(SELECT 1 FROM vault WHERE is_default = $1)").bind(true);
        let default_exists: Boolean = query1.fetch_one(&mut *transaction).await.into_core()?;
        let default_exists = default_exists.to_bool();

        let query = query(
            r#"
        INSERT INTO
            vault (name, path, is_default, is_kms, vault_multiaddr, local_identifier, authority_identifier, authority_multiaddr, credential_scope)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (name)
            DO UPDATE SET
                path = $2, is_default = $3, is_kms = $4,
                vault_multiaddr = $5, local_identifier = $6, authority_identifier = $7, authority_multiaddr = $8, credential_scope = $9"#,
        )
        .bind(name)
        .bind(vault_type.path().map(|p| p.to_string_lossy().to_string()))
        .bind(!default_exists)
        .bind(vault_type.use_aws_kms())
        .bind(vault_type.vault_multiaddr().map(|r| r.to_string()))
        .bind(vault_type.local_identifier().map(|i| i.to_string()))
        .bind(vault_type.authority_identifier().map(|i| i.to_string()))
        .bind(vault_type.authority_multiaddr().map(|r| r.to_string()))
        .bind(vault_type.credential_scope());
        query.execute(&mut *transaction).await.void()?;

        transaction.commit().await.void()?;
        Ok(NamedVault::new(name, vault_type, !default_exists))
    }

    async fn update_vault(&self, name: &str, vault_type: VaultType) -> Result<()> {
        let query = query("UPDATE vault SET \
            path = $1, is_kms = $2, \
            vault_multiaddr = $3, local_identifier = $4, authority_identifier = $5, authority_multiaddr = $6, credential_scope = $7 WHERE name = $8")
            .bind(vault_type.path().map(|p| p.to_string_lossy().to_string()))
            .bind(vault_type.use_aws_kms())
            .bind(vault_type.vault_multiaddr().map(|r| r.to_string()))
            .bind(vault_type.local_identifier().map(|i| i.to_string()))
            .bind(vault_type.authority_identifier().map(|i| i.to_string()))
            .bind(vault_type.authority_multiaddr().map(|r| r.to_string()))
            .bind(vault_type.credential_scope())
            .bind(name);
        query.execute(&*self.database.pool).await.void()
    }

    async fn delete_named_vault(&self, name: &str) -> Result<()> {
        let query = query("DELETE FROM vault WHERE name = $1").bind(name);
        query.execute(&*self.database.pool).await.void()
    }

    async fn get_database_vault(&self) -> Result<Option<NamedVault>> {
        let query = query_as(
            "SELECT name, path, is_default, is_kms, vault_multiaddr, local_identifier, authority_identifier, authority_multiaddr, credential_scope \
            FROM vault WHERE path is NULL");
        let row: Option<VaultRow> = query
            .fetch_optional(&*self.database.pool)
            .await
            .into_core()?;
        row.map(|r| r.named_vault()).transpose()
    }

    async fn get_named_vault(&self, name: &str) -> Result<Option<NamedVault>> {
        let query =
            query_as("SELECT name, path, is_default, is_kms, vault_multiaddr, local_identifier, authority_identifier, authority_multiaddr, credential_scope \
            FROM vault WHERE name = $1").bind(name);
        let row: Option<VaultRow> = query
            .fetch_optional(&*self.database.pool)
            .await
            .into_core()?;
        row.map(|r| r.named_vault()).transpose()
    }

    async fn get_named_vaults(&self) -> Result<Vec<NamedVault>> {
        let query =
            query_as("SELECT name, path, is_default, is_kms, vault_multiaddr, local_identifier, authority_identifier, authority_multiaddr, credential_scope \
            FROM vault");
        let rows: Vec<VaultRow> = query.fetch_all(&*self.database.pool).await.into_core()?;
        rows.iter().map(|r| r.named_vault()).collect()
    }
}

// Database serialization / deserialization

#[derive(FromRow)]
pub(crate) struct VaultRow {
    name: String,
    path: Nullable<String>,
    is_default: Boolean,
    is_kms: Boolean,
    local_identifier: Nullable<String>,
    vault_multiaddr: Nullable<String>,
    authority_identifier: Nullable<String>,
    authority_multiaddr: Nullable<String>,
    credential_scope: Nullable<String>,
}

impl VaultRow {
    pub(crate) fn named_vault(&self) -> Result<NamedVault> {
        Ok(NamedVault::new(
            &self.name,
            self.vault_type()?,
            self.is_default(),
        ))
    }

    pub(crate) fn vault_type(&self) -> Result<VaultType> {
        let vault_type = match self.path.to_option() {
            None => match self.vault_multiaddr.to_option() {
                // if the `vault_multiaddr` is set, it is a remote vault
                Some(vault_multiaddr) => {
                    let missing_field_error_lamba = || {
                        ockam_core::Error::new(
                            Origin::Api,
                            Kind::Serialization,
                            format!("missing field for remote vault '{}'", self.name),
                        )
                    };

                    let local_identifier = self
                        .local_identifier
                        .to_option()
                        .ok_or_else(missing_field_error_lamba)?;
                    let authority_multiaddr = self
                        .authority_multiaddr
                        .to_option()
                        .ok_or_else(missing_field_error_lamba)?;
                    let authority_identifier = self
                        .authority_identifier
                        .to_option()
                        .ok_or_else(missing_field_error_lamba)?;
                    let credential_scope = self
                        .credential_scope
                        .to_option()
                        .ok_or_else(missing_field_error_lamba)?;

                    VaultType::remote(
                        vault_multiaddr.parse()?,
                        local_identifier.try_into()?,
                        authority_multiaddr.parse()?,
                        authority_identifier.try_into()?,
                        credential_scope,
                    )
                }
                None => VaultType::database(UseAwsKms::from(self.is_kms.to_bool())),
            },
            Some(p) => VaultType::local_file(
                PathBuf::from(p).as_path(),
                UseAwsKms::from(self.is_kms.to_bool()),
            ),
        };

        Ok(vault_type)
    }

    pub(crate) fn is_default(&self) -> bool {
        self.is_default.to_bool()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::nodes::service::CredentialScope;
    use ockam_node::database::with_dbs;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_repository() -> Result<()> {
        with_dbs(|db| async move {
            let repository: Arc<dyn VaultsRepository> = Arc::new(VaultsSqlxDatabase::new(db));

            // A vault can be defined with a path and stored under a specific name
            let vault_type = VaultType::local_file("path", UseAwsKms::No);
            let named_vault1 = repository.store_vault("vault1", vault_type.clone()).await?;
            let expected = NamedVault::new("vault1", vault_type.clone(), true);
            assert_eq!(named_vault1, expected);

            // The vault can then be retrieved with its name
            let result = repository.get_named_vault("vault1").await?;
            assert_eq!(result, Some(named_vault1.clone()));

            // Another vault can be created.
            // It is not the default vault
            let vault_type = VaultType::local_file("path2", UseAwsKms::No);
            let named_vault2 = repository.store_vault("vault2", vault_type.clone()).await?;
            let expected = NamedVault::new("vault2", vault_type.clone(), false);
            // it is not the default vault
            assert_eq!(named_vault2, expected);

            // The first vault can be set at another path
            let vault_type = VaultType::local_file("path2", UseAwsKms::No);
            repository
                .update_vault("vault1", vault_type.clone())
                .await?;
            let result = repository.get_named_vault("vault1").await?;
            assert_eq!(result, Some(NamedVault::new("vault1", vault_type, true)));

            // The first vault can be deleted
            repository.delete_named_vault("vault1").await?;
            let result = repository.get_named_vault("vault1").await?;
            assert_eq!(result, None);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_store_kms_vault() -> Result<()> {
        with_dbs(|db| async move {
            let repository: Arc<dyn VaultsRepository> = Arc::new(VaultsSqlxDatabase::new(db));

            // It is possible to create a vault storing its signing keys in an AWS KMS
            let vault_type = VaultType::database(UseAwsKms::Yes);
            let kms = repository.store_vault("kms", vault_type.clone()).await?;
            let expected = NamedVault::new("kms", vault_type, true);
            assert_eq!(kms, expected);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_store_remote_vault() -> Result<()> {
        with_dbs(|db| async move {
            let repository: Arc<dyn VaultsRepository> = Arc::new(VaultsSqlxDatabase::new(db));

            // It is possible to create a remote vault
            let vault_type = VaultType::remote(
                "/secure/api/service/remote_vault".parse().unwrap(),
                "Iabababababababababababababababababababababababababababababababab"
                    .try_into()
                    .unwrap(),
                "/service/authority".parse().unwrap(),
                "Iabababababababababababababababababababababababababababababababab"
                    .try_into()
                    .unwrap(),
                CredentialScope::ProjectMember {
                    project_id: "project_id".to_string(),
                }
                .to_string(),
            );
            // TODO: complete this test
            let remote = repository.store_vault("remote", vault_type.clone()).await?;
            let expected = NamedVault::new("remote", vault_type, true);
            assert_eq!(remote, expected);
            Ok(())
        })
        .await
    }
}
