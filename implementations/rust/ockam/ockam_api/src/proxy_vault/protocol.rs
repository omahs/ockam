use crate::nodes::connection::{Connection, ConnectionInstantiator};
use crate::DefaultAddress;
use minicbor::{CborLen, Decode, Encode};
use ockam::identity::{utils, TimestampInSeconds, Vault};
use ockam_core::{
    async_trait, cbor_encode_preallocate, route, Address, NeutralMessage, Route, Routed, Worker,
};
use ockam_multiaddr::MultiAddr;
use ockam_node::Context;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Encode, Decode, CborLen)]
#[rustfmt::skip]
enum ProxyError {
    #[n(0)] InvalidResponse,
}

impl From<ProxyError> for ockam_core::Error {
    fn from(_error: ProxyError) -> Self {
        todo!()
    }
}

impl From<ockam_core::Error> for ProxyError {
    fn from(_error: ockam_core::Error) -> Self {
        todo!()
    }
}

struct Server {
    vault: Vault,
}

impl Server {
    async fn start_worker(
        context: &Context,
        address: Address,
        vault: Vault,
    ) -> ockam_core::Result<()> {
        let worker = Self { vault };
        context.start_worker(address, worker).await
    }
}

#[async_trait]
impl Worker for Server {
    type Message = NeutralMessage;
    type Context = Context;

    async fn handle_message(
        &mut self,
        context: &mut Self::Context,
        msg: Routed<Self::Message>,
    ) -> ockam_core::Result<()> {
        let local_message = msg.into_local_message();
        let mut onward_route = local_message.onward_route();
        onward_route.step()?;
        let onward_address = onward_route.next()?.clone();
        let return_route = local_message.return_route();
        let payload = local_message.into_payload();

        // TODO: check ACLs
        let response = match onward_address.address() {
            "identity_vault" => {
                vault_for_signing::handle_request(self.vault.identity_vault.as_ref(), payload)
                    .await?
            }
            "secure_channel_vault" => {
                vault_for_secure_channels::handle_request(
                    self.vault.secure_channel_vault.as_ref(),
                    payload,
                )
                .await?
            }
            "credential_vault" => {
                vault_for_signing::handle_request(
                    self.vault.credential_vault.as_ref(),
                    minicbor::decode(&payload)?,
                )
                .await?
            }
            "verifying_vault" => {
                vault_for_verify_signatures::handle_request(
                    self.vault.verifying_vault.as_ref(),
                    payload,
                )
                .await?
            }
            _ => {
                warn!("Unknown address: {}, ignoring request", onward_address);
                return Ok(());
            }
        };

        let response = NeutralMessage::from(response);
        context.send(return_route, response).await?;

        Ok(())
    }
}

struct ConnectionState {
    connection: Option<Connection>,
    last_ping: TimestampInSeconds,
}

struct Client {
    route: MultiAddr,
    connection: Arc<AsyncMutex<ConnectionState>>,
    context: Context,
    instantiator: ConnectionInstantiator,
}

impl Client {
    fn new(context: Context, route: MultiAddr, instantiator: ConnectionInstantiator) -> Self {
        let connection = Arc::new(AsyncMutex::new(ConnectionState {
            connection: None,
            last_ping: utils::now().unwrap(),
        }));

        Self {
            route,
            connection,
            context,
            instantiator,
        }
    }

    /// Verify that the connection is still open by pinging the other end
    /// In case the connection times out, the connection is established again
    async fn assert_connection(&self) -> ockam_core::Result<Route> {
        let mut guard = self.connection.lock().await;
        let now = utils::now()?;
        if let Some(connection) = guard.connection.as_ref() {
            if guard.last_ping + 10 < now {
                connection.route()
            } else {
                let echo_route = route![connection.transport_route(), DefaultAddress::ECHO_SERVICE];
                let result: ockam_core::Result<()> =
                    self.context.send_and_receive(echo_route, ()).await;

                match result {
                    Ok(_) => Ok(connection.route()?),
                    Err(_) => {
                        guard.connection = None;
                        // we need to re-establish the connection
                        todo!("Re-establish connection")
                    }
                }
            }
        } else {
            // we need to establish the connection
            let connection = self
                .instantiator
                .connect(&self.context, &self.route)
                .await?;
            let route = connection.route()?;
            guard.connection = Some(connection);
            guard.last_ping = now;

            Ok(route)
        }
    }

    fn create_for_destination(self: &Arc<Self>, destination: &str) -> Arc<SpecificClient> {
        Arc::new(SpecificClient {
            client: self.clone(),
            destination: destination.into(),
        })
    }
}

// A client with a known address destination
struct SpecificClient {
    client: Arc<Client>,
    destination: Address,
}

impl SpecificClient {
    async fn send_and_receive<RQ, RS>(&self, request: RQ) -> ockam_core::Result<RS>
    where
        RQ: minicbor::Encode<()> + minicbor::CborLen<()>,
        for<'a> RS: minicbor::Decode<'a, ()>,
    {
        let route = self.client.assert_connection().await?;
        let encoded = cbor_encode_preallocate(request)?;
        let response: NeutralMessage = self
            .client
            .context
            .send_and_receive(
                route![route, self.destination.clone()],
                NeutralMessage::from(encoded),
            )
            .await?;

        Ok(minicbor::decode::<RS>(&response.into_vec())?)
    }
}

mod vault_for_signing {
    use crate::proxy_vault::protocol::{ProxyError, SpecificClient};
    use minicbor::{CborLen, Decode, Encode};
    use ockam_core::{async_trait, cbor_encode_preallocate};
    use ockam_vault::{
        Signature, SigningKeyType, SigningSecretKeyHandle, VaultForSigning, VerifyingPublicKey,
    };

    #[derive(Encode, Decode, CborLen)]
    #[rustfmt::skip]
    pub(super) enum Request {
        #[n(0)] Sign {
            #[n(0)] signing_secret_key_handle: SigningSecretKeyHandle,
            #[n(1)] data: Vec<u8>,
        },
        #[n(1)] GenerateSigningSecretKey {
            #[n(0)] signing_key_type: SigningKeyType,
        },
        #[n(2)] GetVerifyingPublicKey {
            #[n(0)] signing_secret_key_handle: SigningSecretKeyHandle,
        },
        #[n(3)] GetSecretKeyHandle {
            #[n(0)] verifying_public_key: VerifyingPublicKey,
        },
        #[n(4)] DeleteSigningSecretKey {
            #[n(0)] signing_secret_key_handle: SigningSecretKeyHandle,
        },
    }

    #[derive(Encode, Decode, CborLen)]
    #[rustfmt::skip]
    enum Response {
        #[n(0)] Sign(#[n(0)] Result<Signature, ProxyError>),
        #[n(1)] SigningSecretKeyHandle(#[n(0)] Result<SigningSecretKeyHandle, ProxyError>),
        #[n(2)] VerifyingPublicKey(#[n(0)] Result<VerifyingPublicKey, ProxyError>),
        #[n(3)] SecretKeyHandle(#[n(0)] Result<SigningSecretKeyHandle, ProxyError>),
        #[n(4)] DeletedSigningSecretKey(#[n(0)] Result<bool, ProxyError>),
    }

    pub(super) async fn handle_request(
        vault: &dyn VaultForSigning,
        request: Vec<u8>,
    ) -> ockam_core::Result<Vec<u8>> {
        let request: Request = minicbor::decode(&request)?;
        let response = match request {
            Request::Sign {
                signing_secret_key_handle,
                data,
            } => {
                let signature = vault
                    .sign(&signing_secret_key_handle, &data)
                    .await
                    .map_err(Into::into);
                Response::Sign(signature)
            }
            Request::GenerateSigningSecretKey { signing_key_type } => {
                let handle = vault
                    .generate_signing_secret_key(signing_key_type)
                    .await
                    .map_err(Into::into);
                Response::SigningSecretKeyHandle(handle)
            }
            Request::GetVerifyingPublicKey {
                signing_secret_key_handle,
            } => {
                let key = vault
                    .get_verifying_public_key(&signing_secret_key_handle)
                    .await
                    .map_err(Into::into);
                Response::VerifyingPublicKey(key)
            }
            Request::GetSecretKeyHandle {
                verifying_public_key,
            } => {
                let handle = vault
                    .get_secret_key_handle(&verifying_public_key)
                    .await
                    .map_err(Into::into);
                Response::SecretKeyHandle(handle)
            }
            Request::DeleteSigningSecretKey {
                signing_secret_key_handle,
            } => {
                let result = vault
                    .delete_signing_secret_key(signing_secret_key_handle)
                    .await
                    .map_err(Into::into);
                Response::DeletedSigningSecretKey(result)
            }
        };

        cbor_encode_preallocate(response)
    }

    #[async_trait]
    impl VaultForSigning for SpecificClient {
        async fn sign(
            &self,
            signing_secret_key_handle: &SigningSecretKeyHandle,
            data: &[u8],
        ) -> ockam_core::Result<Signature> {
            let response: Response = self
                .send_and_receive(Request::Sign {
                    signing_secret_key_handle: signing_secret_key_handle.clone(),
                    data: data.to_vec(),
                })
                .await?;

            let result = match response {
                Response::Sign(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn generate_signing_secret_key(
            &self,
            signing_key_type: SigningKeyType,
        ) -> ockam_core::Result<SigningSecretKeyHandle> {
            let response: Response = self
                .send_and_receive(Request::GenerateSigningSecretKey { signing_key_type })
                .await?;

            let result = match response {
                Response::SigningSecretKeyHandle(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn get_verifying_public_key(
            &self,
            signing_secret_key_handle: &SigningSecretKeyHandle,
        ) -> ockam_core::Result<VerifyingPublicKey> {
            let response: Response = self
                .send_and_receive(Request::GetVerifyingPublicKey {
                    signing_secret_key_handle: signing_secret_key_handle.clone(),
                })
                .await?;

            let result = match response {
                Response::VerifyingPublicKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn get_secret_key_handle(
            &self,
            verifying_public_key: &VerifyingPublicKey,
        ) -> ockam_core::Result<SigningSecretKeyHandle> {
            let response: Response = self
                .send_and_receive(Request::GetSecretKeyHandle {
                    verifying_public_key: verifying_public_key.clone(),
                })
                .await?;

            let result = match response {
                Response::SecretKeyHandle(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn delete_signing_secret_key(
            &self,
            signing_secret_key_handle: SigningSecretKeyHandle,
        ) -> ockam_core::Result<bool> {
            let response: Response = self
                .send_and_receive(Request::DeleteSigningSecretKey {
                    signing_secret_key_handle,
                })
                .await?;

            let result = match response {
                Response::DeletedSigningSecretKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }
    }
}

pub mod vault_for_secure_channels {
    use crate::proxy_vault::protocol::{ProxyError, SpecificClient};
    use minicbor::{CborLen, Decode, Encode};
    use ockam_core::{async_trait, cbor_encode_preallocate};
    use ockam_vault::{
        AeadSecretKeyHandle, HKDFNumberOfOutputs, HashOutput, HkdfOutput, SecretBufferHandle,
        VaultForSecureChannels, X25519PublicKey, X25519SecretKeyHandle,
    };

    pub(super) async fn handle_request(
        vault: &dyn VaultForSecureChannels,
        request: Vec<u8>,
    ) -> ockam_core::Result<Vec<u8>> {
        let request: Request = minicbor::decode(&request)?;
        let response = match request {
            Request::X25519Ecdh {
                secret_key_handle,
                peer_public_key,
            } => {
                let result = vault
                    .x25519_ecdh(&secret_key_handle, &peer_public_key)
                    .await;
                Response::X25519Ecdh(result.map_err(Into::into))
            }
            Request::Hash { data } => {
                let result = vault.hash(&data).await;
                Response::Hash(result.map_err(Into::into))
            }
            Request::Hkdf {
                salt,
                input_key_material,
                number_of_outputs,
            } => {
                let result = vault
                    .hkdf(&salt, input_key_material.as_ref(), number_of_outputs)
                    .await;
                Response::Hkdf(result.map_err(Into::into))
            }
            Request::AeadEncrypt {
                secret_key_handle,
                plain_text,
                nonce,
                aad,
            } => {
                let mut destination = Vec::new();
                let result = vault
                    .aead_encrypt(
                        &mut destination,
                        &secret_key_handle,
                        &plain_text,
                        &nonce,
                        &aad,
                    )
                    .await;
                let result = result.map(|_| destination);
                Response::AeadEncrypt(result.map_err(Into::into))
            }
            Request::AeadDecrypt {
                secret_key_handle,
                cipher_text,
                nonce,
                aad,
            } => {
                let result = vault
                    .aead_decrypt(&secret_key_handle, &cipher_text, &nonce, &aad)
                    .await;
                Response::AeadDecrypt(result.map_err(Into::into))
            }
            Request::PersistAeadKey { secret_key_handle } => {
                let result = vault.persist_aead_key(&secret_key_handle).await;
                Response::PersistAeadKey(result.map_err(Into::into))
            }
            Request::LoadAeadKey { secret_key_handle } => {
                let result = vault.load_aead_key(&secret_key_handle).await;
                Response::LoadAeadKey(result.map_err(Into::into))
            }
            Request::GenerateStaticX25519SecretKey => {
                let result = vault.generate_static_x25519_secret_key().await;
                Response::GenerateStaticX25519SecretKey(result.map_err(Into::into))
            }
            Request::DeleteStaticX25519SecretKey { secret_key_handle } => {
                let result = vault
                    .delete_static_x25519_secret_key(secret_key_handle)
                    .await;
                Response::DeleteStaticX25519SecretKey(result.map_err(Into::into))
            }
            Request::GenerateEphemeralX25519SecretKey => {
                let result = vault.generate_ephemeral_x25519_secret_key().await;
                Response::GenerateEphemeralX25519SecretKey(result.map_err(Into::into))
            }
            Request::DeleteEphemeralX25519SecretKey { secret_key_handle } => {
                let result = vault
                    .delete_ephemeral_x25519_secret_key(secret_key_handle)
                    .await;
                Response::DeleteEphemeralX25519SecretKey(result.map_err(Into::into))
            }
            Request::GetX25519PublicKey { secret_key_handle } => {
                let result = vault.get_x25519_public_key(&secret_key_handle).await;
                Response::GetX25519PublicKey(result.map_err(Into::into))
            }
            Request::GetX25519SecretKeyHandle { public_key } => {
                let result = vault.get_x25519_secret_key_handle(&public_key).await;
                Response::GetX25519SecretKeyHandle(result.map_err(Into::into))
            }
            Request::ImportSecretBuffer { buffer } => {
                let result = vault.import_secret_buffer(buffer).await;
                Response::ImportSecretBuffer(result.map_err(Into::into))
            }
            Request::DeleteSecretBuffer {
                secret_buffer_handle,
            } => {
                let result = vault.delete_secret_buffer(secret_buffer_handle).await;
                Response::DeleteSecretBuffer(result.map_err(Into::into))
            }
            Request::ConvertSecretBufferToAeadKey {
                secret_buffer_handle,
            } => {
                let result = vault
                    .convert_secret_buffer_to_aead_key(secret_buffer_handle)
                    .await;
                Response::ConvertSecretBufferToAeadKey(result.map_err(Into::into))
            }
            Request::DeleteAeadSecretKey { secret_key_handle } => {
                let result = vault.delete_aead_secret_key(secret_key_handle).await;
                Response::DeleteAeadSecretKey(result.map_err(Into::into))
            }
        };
        cbor_encode_preallocate(response)
    }

    #[derive(Encode, Decode, CborLen)]
    #[rustfmt::skip]
    enum Request {
        #[n(0)] X25519Ecdh {
            #[n(0)] secret_key_handle: X25519SecretKeyHandle,
            #[n(1)] peer_public_key: X25519PublicKey,
        },
        #[n(1)] Hash {
            #[n(0)] data: Vec<u8>,
        },
        #[n(2)] Hkdf {
            #[n(0)] salt: SecretBufferHandle,
            #[n(1)] input_key_material: Option<SecretBufferHandle>,
            #[n(2)] number_of_outputs: HKDFNumberOfOutputs,
        },
        #[n(3)] AeadEncrypt {
            #[n(0)] secret_key_handle: AeadSecretKeyHandle,
            #[n(1)] plain_text: Vec<u8>,
            #[n(2)] nonce: Vec<u8>,
            #[n(3)] aad: Vec<u8>,
        },
        #[n(4)] AeadDecrypt {
            #[n(0)] secret_key_handle: AeadSecretKeyHandle,
            #[n(1)] cipher_text: Vec<u8>,
            #[n(2)] nonce: Vec<u8>,
            #[n(3)] aad: Vec<u8>,
        },
        #[n(5)] PersistAeadKey {
            #[n(0)] secret_key_handle: AeadSecretKeyHandle,
        },
        #[n(6)] LoadAeadKey {
            #[n(0)] secret_key_handle: AeadSecretKeyHandle,
        },
        #[n(7)] GenerateStaticX25519SecretKey,
        #[n(8)] DeleteStaticX25519SecretKey {
            #[n(0)] secret_key_handle: X25519SecretKeyHandle,
        },
        #[n(9)] GenerateEphemeralX25519SecretKey,
        #[n(10)] DeleteEphemeralX25519SecretKey {
            #[n(0)] secret_key_handle: X25519SecretKeyHandle,
        },
        #[n(11)] GetX25519PublicKey {
            #[n(0)] secret_key_handle: X25519SecretKeyHandle,
        },
        #[n(12)] GetX25519SecretKeyHandle {
            #[n(0)] public_key: X25519PublicKey,
        },
        #[n(13)] ImportSecretBuffer {
            #[n(0)] buffer: Vec<u8>,
        },
        #[n(14)] DeleteSecretBuffer {
            #[n(0)] secret_buffer_handle: SecretBufferHandle,
        },
        #[n(15)] ConvertSecretBufferToAeadKey {
            #[n(0)] secret_buffer_handle: SecretBufferHandle,
        },
        #[n(16)] DeleteAeadSecretKey {
            #[n(0)] secret_key_handle: AeadSecretKeyHandle,
        },
    }

    #[derive(Encode, Decode, CborLen)]
    #[rustfmt::skip]
    enum Response {
        #[n(0)] X25519Ecdh(#[n(0)] Result<SecretBufferHandle, ProxyError>),
        #[n(1)] Hash(#[n(0)] Result<HashOutput, ProxyError>),
        #[n(2)] Hkdf(#[n(0)] Result<HkdfOutput, ProxyError>),
        #[n(3)] AeadEncrypt(#[n(0)] Result<Vec<u8>, ProxyError>),
        #[n(4)] AeadDecrypt(#[n(0)] Result<Vec<u8>, ProxyError>),
        #[n(5)] PersistAeadKey(#[n(0)] Result<(), ProxyError>),
        #[n(6)] LoadAeadKey(#[n(0)] Result<(), ProxyError>),
        #[n(7)] GenerateStaticX25519SecretKey(#[n(0)] Result<X25519SecretKeyHandle, ProxyError>),
        #[n(8)] DeleteStaticX25519SecretKey(#[n(0)] Result<bool, ProxyError>),
        #[n(9)] GenerateEphemeralX25519SecretKey(#[n(0)] Result<X25519SecretKeyHandle, ProxyError>),
        #[n(10)] DeleteEphemeralX25519SecretKey(#[n(0)] Result<bool, ProxyError>),
        #[n(11)] GetX25519PublicKey(#[n(0)] Result<X25519PublicKey, ProxyError>),
        #[n(12)] GetX25519SecretKeyHandle(#[n(0)] Result<X25519SecretKeyHandle, ProxyError>),
        #[n(13)] ImportSecretBuffer(#[n(0)] Result<SecretBufferHandle, ProxyError>),
        #[n(14)] DeleteSecretBuffer(#[n(0)] Result<bool, ProxyError>),
        #[n(15)] ConvertSecretBufferToAeadKey(#[n(0)] Result<AeadSecretKeyHandle, ProxyError>),
        #[n(16)] DeleteAeadSecretKey(#[n(0)] Result<bool, ProxyError>),
    }

    #[async_trait]
    impl VaultForSecureChannels for SpecificClient {
        async fn x25519_ecdh(
            &self,
            secret_key_handle: &X25519SecretKeyHandle,
            peer_public_key: &X25519PublicKey,
        ) -> ockam_core::Result<SecretBufferHandle> {
            let response: Response = self
                .send_and_receive(Request::X25519Ecdh {
                    secret_key_handle: secret_key_handle.clone(),
                    peer_public_key: peer_public_key.clone(),
                })
                .await?;

            let result = match response {
                Response::X25519Ecdh(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn hash(&self, data: &[u8]) -> ockam_core::Result<HashOutput> {
            let response: Response = self
                .send_and_receive(Request::Hash {
                    data: data.to_vec(),
                })
                .await?;

            let result = match response {
                Response::Hash(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn hkdf(
            &self,
            salt: &SecretBufferHandle,
            input_key_material: Option<&SecretBufferHandle>,
            number_of_outputs: HKDFNumberOfOutputs,
        ) -> ockam_core::Result<HkdfOutput> {
            let response: Response = self
                .send_and_receive(Request::Hkdf {
                    salt: salt.clone(),
                    input_key_material: input_key_material.cloned(),
                    number_of_outputs,
                })
                .await?;

            let result = match response {
                Response::Hkdf(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn aead_encrypt(
            &self,
            destination: &mut Vec<u8>,
            secret_key_handle: &AeadSecretKeyHandle,
            plain_text: &[u8],
            nonce: &[u8],
            aad: &[u8],
        ) -> ockam_core::Result<()> {
            let response: Response = self
                .send_and_receive(Request::AeadEncrypt {
                    secret_key_handle: secret_key_handle.clone(),
                    plain_text: plain_text.to_vec(),
                    nonce: nonce.to_vec(),
                    aad: aad.to_vec(),
                })
                .await?;

            match response {
                Response::AeadEncrypt(result) => {
                    destination.extend(result?);
                    Ok(())
                }
                _ => Err(ProxyError::InvalidResponse)?,
            }
        }

        async fn aead_decrypt(
            &self,
            secret_key_handle: &AeadSecretKeyHandle,
            cipher_text: &[u8],
            nonce: &[u8],
            aad: &[u8],
        ) -> ockam_core::Result<Vec<u8>> {
            let response: Response = self
                .send_and_receive(Request::AeadDecrypt {
                    secret_key_handle: secret_key_handle.clone(),
                    cipher_text: cipher_text.to_vec(),
                    nonce: nonce.to_vec(),
                    aad: aad.to_vec(),
                })
                .await?;

            let result = match response {
                Response::AeadDecrypt(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn persist_aead_key(
            &self,
            secret_key_handle: &AeadSecretKeyHandle,
        ) -> ockam_core::Result<()> {
            let response: Response = self
                .send_and_receive(Request::PersistAeadKey {
                    secret_key_handle: secret_key_handle.clone(),
                })
                .await?;

            match response {
                Response::PersistAeadKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            }

            Ok(())
        }

        async fn load_aead_key(
            &self,
            secret_key_handle: &AeadSecretKeyHandle,
        ) -> ockam_core::Result<()> {
            let response: Response = self
                .send_and_receive(Request::LoadAeadKey {
                    secret_key_handle: secret_key_handle.clone(),
                })
                .await?;

            match response {
                Response::LoadAeadKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            }

            Ok(())
        }

        async fn generate_static_x25519_secret_key(
            &self,
        ) -> ockam_core::Result<X25519SecretKeyHandle> {
            let response: Response = self
                .send_and_receive(Request::GenerateStaticX25519SecretKey)
                .await?;

            let result = match response {
                Response::GenerateStaticX25519SecretKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn delete_static_x25519_secret_key(
            &self,
            secret_key_handle: X25519SecretKeyHandle,
        ) -> ockam_core::Result<bool> {
            let response: Response = self
                .send_and_receive(Request::DeleteStaticX25519SecretKey { secret_key_handle })
                .await?;

            let result = match response {
                Response::DeleteStaticX25519SecretKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn generate_ephemeral_x25519_secret_key(
            &self,
        ) -> ockam_core::Result<X25519SecretKeyHandle> {
            let response: Response = self
                .send_and_receive(Request::GenerateEphemeralX25519SecretKey)
                .await?;

            let result = match response {
                Response::GenerateEphemeralX25519SecretKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn delete_ephemeral_x25519_secret_key(
            &self,
            secret_key_handle: X25519SecretKeyHandle,
        ) -> ockam_core::Result<bool> {
            let response: Response = self
                .send_and_receive(Request::DeleteEphemeralX25519SecretKey { secret_key_handle })
                .await?;

            let result = match response {
                Response::DeleteEphemeralX25519SecretKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn get_x25519_public_key(
            &self,
            secret_key_handle: &X25519SecretKeyHandle,
        ) -> ockam_core::Result<X25519PublicKey> {
            let response: Response = self
                .send_and_receive(Request::GetX25519PublicKey {
                    secret_key_handle: secret_key_handle.clone(),
                })
                .await?;

            let result = match response {
                Response::GetX25519PublicKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn get_x25519_secret_key_handle(
            &self,
            public_key: &X25519PublicKey,
        ) -> ockam_core::Result<X25519SecretKeyHandle> {
            let response: Response = self
                .send_and_receive(Request::GetX25519SecretKeyHandle {
                    public_key: public_key.clone(),
                })
                .await?;

            let result = match response {
                Response::GetX25519SecretKeyHandle(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn import_secret_buffer(
            &self,
            buffer: Vec<u8>,
        ) -> ockam_core::Result<SecretBufferHandle> {
            let response: Response = self
                .send_and_receive(Request::ImportSecretBuffer { buffer })
                .await?;

            let result = match response {
                Response::ImportSecretBuffer(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn delete_secret_buffer(
            &self,
            secret_buffer_handle: SecretBufferHandle,
        ) -> ockam_core::Result<bool> {
            let response: Response = self
                .send_and_receive(Request::DeleteSecretBuffer {
                    secret_buffer_handle,
                })
                .await?;

            let result = match response {
                Response::DeleteSecretBuffer(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn convert_secret_buffer_to_aead_key(
            &self,
            secret_buffer_handle: SecretBufferHandle,
        ) -> ockam_core::Result<AeadSecretKeyHandle> {
            let response: Response = self
                .send_and_receive(Request::ConvertSecretBufferToAeadKey {
                    secret_buffer_handle,
                })
                .await?;

            let result = match response {
                Response::ConvertSecretBufferToAeadKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn delete_aead_secret_key(
            &self,
            secret_key_handle: AeadSecretKeyHandle,
        ) -> ockam_core::Result<bool> {
            let response: Response = self
                .send_and_receive(Request::DeleteAeadSecretKey { secret_key_handle })
                .await?;

            let result = match response {
                Response::DeleteAeadSecretKey(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }
    }
}

pub mod vault_for_verify_signatures {
    use crate::proxy_vault::protocol::{ProxyError, SpecificClient};
    use minicbor::{CborLen, Decode, Encode};
    use ockam_core::{async_trait, cbor_encode_preallocate};
    use ockam_vault::{Sha256Output, Signature, VaultForVerifyingSignatures, VerifyingPublicKey};

    pub(super) async fn handle_request(
        vault: &dyn VaultForVerifyingSignatures,
        request: Vec<u8>,
    ) -> ockam_core::Result<Vec<u8>> {
        let request: Request = minicbor::decode(&request)?;
        let response = match request {
            Request::Sha256 { data } => {
                let result = vault.sha256(&data).await;
                Response::Sha256(result.map_err(Into::into))
            }
            Request::VerifySignature {
                verifying_public_key,
                data,
                signature,
            } => {
                let result = vault
                    .verify_signature(&verifying_public_key, &data, &signature)
                    .await;
                Response::VerifySignature(result.map_err(Into::into))
            }
        };
        cbor_encode_preallocate(response)
    }

    #[derive(Encode, Decode, CborLen)]
    #[rustfmt::skip]
    enum Request {
        #[n(0)] Sha256 {
            #[n(0)] data: Vec<u8>,
        },
        #[n(1)] VerifySignature {
            #[n(0)] verifying_public_key: VerifyingPublicKey,
            #[n(1)] data: Vec<u8>,
            #[n(2)] signature: Signature,
        },
    }

    #[derive(Encode, Decode, CborLen)]
    #[rustfmt::skip]
    enum Response {
        #[n(0)] Sha256(#[n(0)] Result<Sha256Output, ProxyError>),
        #[n(1)] VerifySignature(#[n(0)] Result<bool, ProxyError>),
    }

    #[async_trait]
    impl VaultForVerifyingSignatures for SpecificClient {
        async fn sha256(&self, data: &[u8]) -> ockam_core::Result<Sha256Output> {
            let response: Response = self
                .send_and_receive(Request::Sha256 {
                    data: data.to_vec(),
                })
                .await?;

            let result = match response {
                Response::Sha256(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }

        async fn verify_signature(
            &self,
            verifying_public_key: &VerifyingPublicKey,
            data: &[u8],
            signature: &Signature,
        ) -> ockam_core::Result<bool> {
            let response: Response = self
                .send_and_receive(Request::VerifySignature {
                    verifying_public_key: verifying_public_key.clone(),
                    data: data.to_vec(),
                    signature: signature.clone(),
                })
                .await?;

            let result = match response {
                Response::VerifySignature(result) => result?,
                _ => Err(ProxyError::InvalidResponse)?,
            };

            Ok(result)
        }
    }
}

pub fn create_vault(
    context: Context,
    route: MultiAddr,
    instantiator: ConnectionInstantiator,
) -> Vault {
    let client = Arc::new(Client::new(context, route, instantiator));
    Vault::new(
        client.create_for_destination("identity_vault"),
        client.create_for_destination("secure_channel_vault"),
        client.create_for_destination("credential_vault"),
        client.create_for_destination("verifying_vault"),
    )
}

pub async fn start_server(
    context: &Context,
    address: Address,
    vault: Vault,
) -> ockam_core::Result<()> {
    Server::start_worker(context, address, vault).await
}
