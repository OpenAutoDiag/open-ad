//! Implementation of the UDS ECU Reset service based on ISO 14229-1:2020 section 10.3.
//!
//! The ECUReset service is used by the client to request a server reset.
//! This service requests the server to effectively perform a server reset based
//! on the content of the `reset_type` parameter value embedded in the ECUReset
//! request message.
//!
//! For more, see [`EcuReset`].

use std::{io::Read, sync::Arc, time::Duration};

use tokio::sync::Mutex;

use super::ServiceId;
use crate::{
    try_match_service_id, try_negative_response,
    uds::{self, ClientError, UdsResponse},
};

/// ECUReset (`0x11`) service implementation.
pub struct EcuReset;

impl EcuReset {
    /// Creates a new instance of the ECUReset service.
    pub fn new() -> Self {
        EcuReset {}
    }

    /// Sends a reset request to the UDS server.
    ///
    /// # Arguments
    ///
    /// * `client` - The UDS client to use for sending the request.
    /// * `reset_type` - The type of reset to perform.
    /// * `timeout` - The maximum time to wait for a response.
    ///
    /// # Returns
    ///
    /// A [`UdsResponse<EcuResetResponse>`][UdsResponse] containing the response from the server.
    ///
    /// # Errors
    ///
    /// Returns a [ClientError] if the request fails.
    ///
    /// # Example
    /// ```no_run
    /// use std::{net::{IpAddr, Ipv4Addr}, sync::Arc};
    /// use open_uds::{services, uds::{self, ClientError}};
    /// use tokio::sync::Mutex;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), ClientError> {
    ///     let config = uds::ClientConfig {
    ///         source_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ///         source_logical_address: 0x0E00,
    ///         target_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ///         target_logical_address: 0x000A,
    ///     };
    ///
    ///     let client = uds::UdsClient::connect(config).await.unwrap();
    ///     let client = Arc::new(Mutex::new(client));
    ///
    ///     let ecu_reset_srv = services::ecu_reset::EcuReset::new();
    ///
    ///     let response = ecu_reset_srv
    ///         .reset(client, services::ecu_reset::ResetType::HardReset, None)
    ///         .await?;
    ///
    ///     println!("{:?}", response);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// The `timeout` parameter is optional and can be used to specify the
    /// maximum time to wait for a response. If the `timeout` parameter is not
    /// provided, the default timeout will be used (5s).
    pub async fn reset(
        &self,
        client: Arc<Mutex<dyn uds::Client>>,
        reset_type: ResetType,
        timeout: Option<Duration>,
    ) -> Result<UdsResponse<EcuResetResponse>, ClientError> {
        let raw_response = client
            .lock()
            .await
            .send_request(ServiceId::ECUReset, reset_type as u8, vec![], timeout)
            .await?;

        let mut reader = std::io::Cursor::new(raw_response);
        let mut response_id = [0u8; 1];
        reader.read_exact(&mut response_id)?;

        let service_id = ServiceId::try_from(response_id[0])?;
        try_negative_response!(service_id, reader);
        try_match_service_id!(service_id, ServiceId::ECUReset);

        let ecu_reset_resp = EcuResetResponse::read(&mut reader)?;
        Ok(UdsResponse::Positive(ecu_reset_resp))
    }
}

/// ECUReset response message.
///
/// The ECUReset response message is sent by the server in response to an ECUReset request.
/// The response message contains the reset type and, if the reset type is `EnableRapidPowerShutDown`,
/// the power down time.
#[derive(Debug, Eq, PartialEq)]
pub struct EcuResetResponse {
    pub reset_type: ResetType,
    pub power_down_time: Option<u8>,
}

impl EcuResetResponse {
    pub fn read<T: Read>(reader: &mut T) -> Result<Self, ClientError> {
        let mut reset_type = [0; 1];
        reader.read_exact(&mut reset_type)?;

        let reset_type = ResetType::try_from(reset_type[0])?;
        let power_down_time = if reset_type == ResetType::EnableRapidPowerShutDown {
            let mut power_down_time = [0; 1];
            reader.read_exact(&mut power_down_time)?;
            Some(power_down_time[0])
        } else {
            None
        };

        Ok(EcuResetResponse {
            reset_type,
            power_down_time,
        })
    }
}

/// Enumeration of the possible reset types per ISO 14229-1:2020, table 36.
#[repr(u8)]
#[derive(Debug, Clone, Copy, strum_macros::Display, PartialEq, Eq)]
pub enum ResetType {
    HardReset = 0x01,
    KeyOffReset = 0x02,
    SoftReset = 0x03,
    EnableRapidPowerShutDown = 0x04,
    DisableRapidPowerShutDown = 0x05,
}

impl TryFrom<u8> for ResetType {
    type Error = ClientError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(ResetType::HardReset),
            0x02 => Ok(ResetType::KeyOffReset),
            0x03 => Ok(ResetType::SoftReset),
            0x04 => Ok(ResetType::EnableRapidPowerShutDown),
            0x05 => Ok(ResetType::DisableRapidPowerShutDown),
            _ => Err(ClientError::InvalidResetType(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::nrc;

    use super::*;

    #[test]
    fn test_reset_type_try_from() {
        assert_eq!(ResetType::try_from(0x01).unwrap(), ResetType::HardReset);
        assert_eq!(ResetType::try_from(0x02).unwrap(), ResetType::KeyOffReset);
        assert_eq!(ResetType::try_from(0x03).unwrap(), ResetType::SoftReset);
        assert_eq!(
            ResetType::try_from(0x04).unwrap(),
            ResetType::EnableRapidPowerShutDown
        );
        assert_eq!(
            ResetType::try_from(0x05).unwrap(),
            ResetType::DisableRapidPowerShutDown
        );
    }

    #[test]
    fn test_reset_type_into() {
        assert_eq!(ResetType::HardReset as u8, 0x01);
        assert_eq!(ResetType::KeyOffReset as u8, 0x02);
        assert_eq!(ResetType::SoftReset as u8, 0x03);
        assert_eq!(ResetType::EnableRapidPowerShutDown as u8, 0x04);
        assert_eq!(ResetType::DisableRapidPowerShutDown as u8, 0x05);
    }

    #[test]
    fn test_ecu_reset_response_read() {
        let data = [0x04, 0x02];
        let mut reader = std::io::Cursor::new(&data);
        let response = EcuResetResponse::read(&mut reader).unwrap();

        assert_eq!(response.reset_type, ResetType::EnableRapidPowerShutDown);
        assert_eq!(response.power_down_time, Some(0x02));
    }

    #[test]
    fn test_ecu_reset_response_read_no_power_down_time() {
        let data = [0x03];
        let mut reader = std::io::Cursor::new(&data);
        let response = EcuResetResponse::read(&mut reader).unwrap();

        assert_eq!(response.reset_type, ResetType::SoftReset);
        assert_eq!(response.power_down_time, None);
    }

    #[test]
    fn test_ecu_reset_response_read_invalid_reset_type() {
        let data = [0x06];
        let mut reader = std::io::Cursor::new(&data);
        let response = EcuResetResponse::read(&mut reader);

        assert!(response.is_err());
    }

    #[test]
    fn test_ecu_reset_response_read_invalid_power_down_time() {
        let data = [0x04];
        let mut reader = std::io::Cursor::new(&data);
        let response = EcuResetResponse::read(&mut reader);

        assert!(response.is_err());
    }

    #[tokio::test]
    async fn test_handle_reset_response() {
        let client = Arc::new(Mutex::new(uds::MockClient::new()));
        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| Ok(vec![0x11, 0x01]));

        let srv = EcuReset::new();
        let resp = srv.reset(client, ResetType::HardReset, None).await.unwrap();

        match resp {
            UdsResponse::Positive(resp) => {
                assert_eq!(resp.reset_type, ResetType::HardReset);
                assert_eq!(resp.power_down_time, None);
            }
            UdsResponse::Negative(_) => panic!("Expected positive response"),
        };
    }

    #[tokio::test]
    async fn test_handle_reset_response_negative_response() {
        let client = Arc::new(Mutex::new(uds::MockClient::new()));
        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| Ok(vec![0x47, 0x01, 0x11]));

        let srv = EcuReset::new();
        let resp = srv.reset(client, ResetType::HardReset, None).await.unwrap();

        match resp {
            UdsResponse::Positive(_) => panic!("Expected negative response"),
            UdsResponse::Negative(rc) => {
                assert_eq!(rc, nrc::NegativeResponseCode::ServiceNotSupported)
            }
        };
    }

    #[tokio::test]
    async fn test_handle_reset_response_service_id_mismatch() {
        let client = Arc::new(Mutex::new(uds::MockClient::new()));
        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| Ok(vec![0x3E, 0x00]));

        let srv = EcuReset::new();
        let resp = srv.reset(client, ResetType::HardReset, None).await;

        assert!(resp.is_err());
    }

    #[test]
    fn test_handle_reset_response_invalid_service_id() {
        let data = [0x3E, 0x00, 0x00];
        let response = EcuResetResponse::read(&mut std::io::Cursor::new(&data));

        assert!(response.is_err());
    }

    #[test]
    fn test_handle_reset_response_invalid_reset_type() {
        let data = [0x11, 0x06, 0x00];
        let response = EcuResetResponse::read(&mut std::io::Cursor::new(&data));

        assert!(response.is_err());
    }

    #[test]
    fn test_handle_reset_response_invalid_power_down_time() {
        let data = [0x11, 0x04, 0x00];
        let response = EcuResetResponse::read(&mut std::io::Cursor::new(&data));

        assert!(response.is_err());
    }
}
