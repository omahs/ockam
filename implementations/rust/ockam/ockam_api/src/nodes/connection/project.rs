use crate::error::ApiError;
use crate::nodes::connection::{Changes, Instantiator};
use crate::{multiaddr_to_route, try_address_to_multiaddr, CliState};
use std::sync::Arc;

use ockam_core::{async_trait, Route};
use ockam_multiaddr::proto::Project;
use ockam_multiaddr::{Match, MultiAddr, Protocol};
use ockam_node::Context;

use ockam::identity::{
    CredentialRetrieverCreator, Identifier, SecureChannelOptions, SecureChannels,
};
use ockam_transport_tcp::TcpTransport;
use std::time::Duration;

/// Creates a secure connection to the project using provided credential
pub(crate) struct ProjectInstantiator {
    identifier: Identifier,
    timeout: Option<Duration>,
    cli_state: CliState,
    secure_channels: Arc<SecureChannels>,
    tcp_transport: TcpTransport,
    credential_retriever_creator: Option<Arc<dyn CredentialRetrieverCreator>>,
}

impl ProjectInstantiator {
    pub fn new(
        identifier: Identifier,
        timeout: Option<Duration>,
        cli_state: CliState,
        tcp_transport: TcpTransport,
        secure_channels: Arc<SecureChannels>,
        credential_retriever_creator: Option<Arc<dyn CredentialRetrieverCreator>>,
    ) -> Self {
        Self {
            identifier,
            timeout,
            cli_state,
            secure_channels,
            tcp_transport,
            credential_retriever_creator,
        }
    }
}

#[async_trait]
impl Instantiator for ProjectInstantiator {
    fn matches(&self) -> Vec<Match> {
        vec![Project::CODE.into()]
    }

    async fn instantiate(
        &self,
        context: &Context,
        _transport_route: Route,
        extracted: (MultiAddr, MultiAddr, MultiAddr),
    ) -> Result<Changes, ockam_core::Error> {
        let (_before, project_piece, after) = extracted;

        let project_protocol_value = project_piece
            .first()
            .ok_or_else(|| ApiError::core("missing project protocol in multiaddr"))?;

        let project = project_protocol_value
            .cast::<Project>()
            .ok_or_else(|| ApiError::core("invalid project protocol in multiaddr"))?;

        let project = self
            .cli_state
            .projects()
            .get_project_by_name(&project)
            .await?;

        let project_identifier = project
            .project_identifier()
            .ok_or_else(|| ApiError::core("Project identifier is missing"))?;
        let project_multiaddr = project.project_multiaddr().cloned()?;

        debug!(addr = %project_multiaddr, "creating secure channel");
        let tcp = multiaddr_to_route(&project_multiaddr, &self.tcp_transport)
            .await
            .ok_or_else(|| {
                ApiError::core(format!(
                    "Couldn't convert MultiAddr to route: project_multiaddr={project_multiaddr}"
                ))
            })?;

        debug!("create a secure channel to the project {project_identifier}");

        let options = SecureChannelOptions::new().with_authority(project_identifier);

        let options =
            if let Some(credential_retriever_creator) = self.credential_retriever_creator.clone() {
                options.with_credential_retriever_creator(credential_retriever_creator)?
            } else {
                options
            };

        let options = if let Some(timeout) = self.timeout {
            options.with_timeout(timeout)
        } else {
            options
        };

        let secure_channel = self
            .secure_channels
            .create_secure_channel(context, &self.identifier.clone(), tcp.route, options)
            .await?;

        // when creating a secure channel, we want the route to pass through that
        // ignoring previous steps, since they will be implicit
        let mut current_multiaddr =
            try_address_to_multiaddr(secure_channel.encryptor_address()).unwrap();
        current_multiaddr.try_extend(after.iter())?;

        Ok(Changes {
            flow_control_id: Some(secure_channel.flow_control_id().clone()),
            current_multiaddr,
            secure_channel_encryptors: vec![secure_channel.encryptor_address().clone()],
            tcp_connection: tcp.tcp_connection,
        })
    }
}
