use async_trait::async_trait;
use mockall::*;
use open_doip::doip_tokio;

use std::{
    fmt::Debug,
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use thiserror::Error;

use crate::{nrc, services};

const DEFAULT_TIMEOUT_SECS: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Failed to connect to DoIP")]
    DoIpError(#[from] doip_tokio::DoIpTokioError),
    #[error("Failed to initialize client")]
    InitError,
    #[error("Failed to write request")]
    Timeout,
    #[error("Failed to write request")]
    WriteError,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Invalid response code {0:X}")]
    InvalidResponseCode(u8),
    #[error("Invalid reset type {0:X}")]
    InvalidResetType(u8),
    #[error("Invalid service ID {0:X}")]
    InvalidServiceId(u8),
    #[error("Server responded with an mismatching security access type in response {0:X}")]
    MismatchingSecurityAccess(u8),
}

pub struct Request {
    pub service_id: services::ServiceId,
    pub subfunction: u8,
    pub data: Vec<u8>,
}

impl Request {
    pub fn write<T: Write>(&self, writer: &mut T) -> std::io::Result<()> {
        writer.write_all(&[self.service_id as u8, self.subfunction])?;
        writer.write_all(&self.data)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Response<T: Debug> {
    pub service_id: services::ServiceId,
    pub subfunction: u8,
    pub response_code: nrc::NegativeResponseCode,
    pub data: Option<T>,
}

#[derive(Debug)]
pub struct ClientConfig {
    pub source_address: IpAddr,
    pub source_logical_address: u16,
    pub target_address: IpAddr,
    pub target_logical_address: u16,
}

#[automock]
#[async_trait]
pub trait Client: Send + Sync {
    async fn send_request(
        &mut self,
        service_id: services::ServiceId,
        subfunction: u8,
        data: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, ClientError>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum UdsResponse<T: Debug + Eq + PartialEq> {
    Positive(T),
    Negative(nrc::NegativeResponseCode),
}

pub struct UdsClient {
    config: ClientConfig,
    // @todo Replace with open-doip when ready
    transport: doip_tokio::DoIpClient,
}

impl UdsClient {
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let transport_options = doip_tokio::DoIpClientOptions {
            target_addr: SocketAddr::new(config.target_address, 13400),
            target_logical_address: config.target_logical_address,
            client_addr: config.source_address,
            client_logical_addr: config.source_logical_address,
        };

        let transport = doip_tokio::DoIpClient::connect_with(&transport_options).await?;

        Ok(Self { config, transport })
    }
}

#[async_trait]
impl Client for UdsClient {
    async fn send_request(
        &mut self,
        service_id: services::ServiceId,
        subfunction: u8,
        data: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, ClientError> {
        let mut payload = Vec::with_capacity(1 /* SID */ + 1 /* Sub-Function*/ + data.len());
        let request = Request {
            service_id,
            subfunction,
            data,
        };
        request
            .write(&mut payload)
            .map_err(|_| ClientError::WriteError)?;

        let response = self
            .transport
            .diagnostic_message(
                self.config.source_logical_address.to_be_bytes(),
                self.config.target_logical_address.to_be_bytes(),
                payload,
                timeout.unwrap_or(DEFAULT_TIMEOUT_SECS),
            )
            .await?;

        Ok(response.user_data)
    }
}
