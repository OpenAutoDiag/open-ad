//! Implementation of the UDS Security Access service based on ISO 14229-1:2020
//! section 10.4.
//!
//!
//! The purpose of this service is to provide a means to access data and/or
//! diagnostic services, which have restricted access for security, emissions,
//! or safety reasons. Diagnostic services for downloading/uploading routines or
//! data into a server and reading specific memory locations from a server are
//! situations where security access may be required. Improper routines or data
//! downloaded into a server could potentially damage the electronics or other
//! vehicle components or risk the vehicle’s compliance to emission, safety, or
//! security standards. The security concept uses a seed and key relationship.
//!
//! A typical example of the use of this service is as follows:
//!
//! — Client requests the “Seed”,
//!
//! — Server sends the “Seed”,
//!
//! — Client sends the “Key” (appropriate for the Seed received),
//!
//! — Server responds that the “Key” was valid and that it will unlock itself.
//!
//! For mroe, see [`SecurityAccess`].
use std::{io::Read, sync::Arc, time::Duration};

use tokio::sync::Mutex;

use crate::{
    try_match_service_id, try_negative_response,
    uds::{self, ClientError, UdsResponse},
};

use super::ServiceId;

/// Security Accesss (`0x27`) service implementation.
pub struct SecurityAccess;

impl SecurityAccess {
    /// Creates a new instance of the SecurityAccess service.
    pub fn new() -> Self {
        SecurityAccess {}
    }

    /// Sends a security access request to the UDS server.
    ///
    /// # Arguments
    /// * `client` - The UDS client to use for sending the request.
    /// * `security_access_type` - The type of security access to perform.
    /// * `data_record` - Optinal user data record to send to the server.
    /// * `timeout` - The maximum time to wait for a response.
    ///
    /// # Returns
    ///
    /// A [`UdsResponse<SASeed>`][UdsResponse] containing the response from the
    /// server.
    ///
    /// # Errors
    ///
    /// Returns a [ClientError] if the request fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::{
    ///     net::{IpAddr, Ipv4Addr},
    ///     sync::Arc,
    /// };
    ///
    /// use tokio::sync::Mutex;
    ///
    /// use open_uds::{
    ///     services,
    ///     uds::{self, ClientError},
    /// };
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), ClientError> {
    ///     let config = uds::ClientConfig {
    ///         source_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ///         source_logical_address: 0x0E00,
    ///         target_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ///         target_logical_address: 0x000A,
    ///     };
    ///     let client = uds::UdsClient::connect(config).await.unwrap();
    ///     let client = Arc::new(Mutex::new(client));
    ///     let security_access_srv = services::security_access::SecurityAccess::new();
    ///     let response = security_access_srv
    ///         .request_seed(
    ///             client,
    ///             services::security_access::SecurityAccessType(1),
    ///             Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    ///             Some(std::time::Duration::from_secs(10)),
    ///         )
    ///         .await?;
    ///     println!("Seed: {:?}", response);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// The `data_record` parameter is optional and can be used to send user
    /// data to the server.
    ///
    /// The `timeout` parameter is optional and can be used to specify the
    /// maximum time to wait for a response. If the `timeout` parameter is not
    /// provided, the default timeout will be used (5s).
    pub async fn request_seed(
        &self,
        client: Arc<Mutex<dyn uds::Client>>,
        security_access_type: SecurityAccessType,
        data_record: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<UdsResponse<SecurityAccessSeed>, ClientError> {
        let data_record = data_record.unwrap_or(vec![]);

        let raw_response = client
            .lock()
            .await
            .send_request(
                ServiceId::SecurityAccess,
                security_access_type.0,
                data_record,
                timeout,
            )
            .await?;

        let mut reader = std::io::Cursor::new(raw_response);
        let mut response_id = [0u8; 1];
        reader.read_exact(&mut response_id)?;

        let service_id = ServiceId::try_from(response_id[0])?;
        try_negative_response!(service_id, reader);
        try_match_service_id!(service_id, ServiceId::SecurityAccess);

        let mut security_access_type_resp = [0u8; 1];
        reader.read_exact(&mut security_access_type_resp)?;

        if SecurityAccessType(security_access_type_resp[0]) != security_access_type {
            return Err(ClientError::MismatchingSecurityAccess(
                security_access_type_resp[0],
            ));
        }

        let mut seed = SecurityAccessSeed(vec![]);
        reader.read_to_end(&mut seed.0)?;

        Ok(UdsResponse::Positive(seed))
    }

    /// Sends a security access key to the UDS server.
    ///
    /// # Arguments
    /// * `client` - The UDS client to use for sending the request.
    /// * `security_access_type` - The type of security access to perform.
    /// * `key` - The key to send to the server.
    /// * `timeout` - The maximum time to wait for a response.
    ///
    /// # Returns
    ///
    /// A [`UdsResponse<SecurityAccessType>`][UdsResponse] containing the response
    /// from the server.
    ///
    /// # Errors
    ///
    /// Returns a [ClientError] if the request fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::{
    ///     net::{IpAddr, Ipv4Addr},
    ///     sync::Arc,
    /// };
    ///
    /// use tokio::sync::Mutex;
    ///
    /// use open_uds::{
    ///     services,
    ///     uds::{self, ClientError},
    /// };
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), ClientError> {
    ///     let config = uds::ClientConfig {
    ///         source_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ///         source_logical_address: 0x0E00,
    ///         target_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ///         target_logical_address: 0x000A,
    ///     };
    ///     let client = uds::UdsClient::connect(config).await.unwrap();
    ///     let client = Arc::new(Mutex::new(client));
    ///     let security_access_srv = services::security_access::SecurityAccess::new();
    ///     let response = security_access_srv
    ///         .send_key(
    ///             client,
    ///             services::security_access::SecurityAccessType(1),
    ///             vec![0xDE, 0xAD, 0xBE, 0xEF],
    ///             Some(std::time::Duration::from_secs(10)),
    ///         )
    ///         .await?;
    ///     println!("Send key response: {:?}", response);
    ///     Ok(())
    /// }
    /// ```
    ///
    pub async fn send_key(
        &self,
        client: Arc<Mutex<dyn uds::Client>>,
        security_access_type: SecurityAccessType,
        key: Vec<u8>,
        timeout: Option<std::time::Duration>,
    ) -> Result<UdsResponse<SecurityAccessType>, ClientError> {
        // ISO 14229-1: The corresponding ‘sendKey' [security_access_type]
        // SubFunction parameter value for the same security level shall equal
        // the 'requestSeed' SubFunction parameter value plus one.
        let security_access_type = security_access_type.0 + 1;

        let raw_response = client
            .lock()
            .await
            .send_request(
                ServiceId::SecurityAccess,
                security_access_type,
                key,
                timeout,
            )
            .await?;

        let mut reader = std::io::Cursor::new(raw_response);
        let mut response_id = [0u8; 1];
        reader.read_exact(&mut response_id)?;

        let service_id = ServiceId::try_from(response_id[0])?;
        try_negative_response!(service_id, reader);
        try_match_service_id!(service_id, ServiceId::SecurityAccess);

        let mut resp_security_access_type = [0u8; 1];
        reader.read_exact(&mut resp_security_access_type)?;

        if resp_security_access_type[0] != security_access_type {
            return Err(ClientError::MismatchingSecurityAccess(
                resp_security_access_type[0],
            ));
        }

        Ok(UdsResponse::Positive(SecurityAccessType(
            resp_security_access_type[0],
        )))
    }
}

/// Security Access Type.
///
/// The Security Access Type is used to specify the type of security access to
/// perform.
///
/// # Example
///
/// ```rust
/// use open_uds::services::security_access::SecurityAccessType;
///
/// let security_access_type = SecurityAccessType(0x01);
/// ```
///
/// # Note
///
/// The Security Access Type is an 8-bit unsigned integer that must be an odd
/// number between `0x01`, `0x05`, `0x07` to `0x41`.
#[derive(Debug, Eq, PartialEq)]
pub struct SecurityAccessType(pub u8);

/// Security Access Seed.
///
/// The Security Access Seed is used to store the seed value received from the
/// server.
#[derive(Debug, Eq, PartialEq)]
pub struct SecurityAccessSeed(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use crate::{nrc, services::ServiceId};

    use super::*;
    use uds::MockClient;

    #[tokio::test]
    async fn test_request_seed() {
        let security_access_srv = SecurityAccess::new();
        let client = Arc::new(Mutex::new(MockClient::new()));

        client
            .lock()
            .await
            .expect_send_request()
            .withf(move |service_id, subfunction, data, timeout| {
                *service_id == ServiceId::SecurityAccess
                    && *subfunction == 1
                    && *data == vec![0xDE, 0xAD, 0xBE, 0xEF]
                    && *timeout == Some(Duration::from_secs(10))
            })
            .returning(|_, _, _, _| {
                Ok(vec![
                    (ServiceId::SecurityAccess as u8) + 0x40, // Response ID
                    SecurityAccessType(1).0,                  // Security Access Type
                    0x02,                                     // Security seed #1
                    0x03,                                     // Security seed #2
                    0x04,                                     // Security seed #3
                    0x05,                                     // Security seed #4
                ])
            });

        let response = security_access_srv
            .request_seed(
                client,
                SecurityAccessType(1),
                Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                Some(Duration::from_secs(10)),
            )
            .await
            .unwrap();

        assert_eq!(
            response,
            UdsResponse::Positive(SecurityAccessSeed(vec![0x02, 0x03, 0x04, 0x05]))
        );
    }

    #[tokio::test]
    async fn test_request_key_required_time_delay_not_expired() {
        let security_access_srv = SecurityAccess::new();
        let client = Arc::new(Mutex::new(MockClient::new()));

        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| {
                Ok(vec![
                    ServiceId::NegativeResponse as u8, // Response ID
                    ServiceId::SecurityAccess as u8,   // Security Access Type
                    nrc::NegativeResponseCode::RequiredTimeDelayNotExpired as u8, // NRC
                ])
            });

        let response = security_access_srv
            .request_seed(
                client,
                SecurityAccessType(1),
                Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                Some(Duration::from_secs(10)),
            )
            .await
            .unwrap();

        assert!(matches!(
            response,
            UdsResponse::Negative(nrc::NegativeResponseCode::RequiredTimeDelayNotExpired)
        ));
    }

    #[tokio::test]
    async fn test_request_seed_required_time_delay_not_expired() {
        let security_access_srv = SecurityAccess::new();
        let client = Arc::new(Mutex::new(MockClient::new()));

        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| {
                Ok(vec![
                    ServiceId::NegativeResponse as u8, // Response ID
                    ServiceId::SecurityAccess as u8,   // Security Access Type
                    nrc::NegativeResponseCode::RequiredTimeDelayNotExpired as u8, // NRC
                ])
            });

        let response = security_access_srv
            .request_seed(
                client,
                SecurityAccessType(1),
                Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                Some(Duration::from_secs(10)),
            )
            .await
            .unwrap();

        assert!(matches!(
            response,
            UdsResponse::Negative(nrc::NegativeResponseCode::RequiredTimeDelayNotExpired)
        ));
    }

    #[tokio::test]
    async fn test_send_key() {
        let security_access_srv = SecurityAccess::new();
        let client = Arc::new(Mutex::new(MockClient::new()));

        client
            .lock()
            .await
            .expect_send_request()
            .withf(|_, subfunction, data, timeout| {
                *subfunction == 2 && *data == vec![0xDE, 0xAD, 0xBE, 0xEF] && *timeout == None
            })
            .returning(|_, _, _, _| {
                Ok(vec![
                    (ServiceId::SecurityAccess as u8) + 0x40, // Response ID
                    0x02,                                     // Security Access Type
                ])
            });

        let response = security_access_srv
            .send_key(
                client,
                SecurityAccessType(1),
                vec![0xDE, 0xAD, 0xBE, 0xEF],
                None,
            )
            .await
            .unwrap();

        assert_eq!(response, UdsResponse::Positive(SecurityAccessType(2)));
    }

    #[tokio::test]
    async fn test_send_key_mismatching_security_access() {
        let security_access_srv = SecurityAccess::new();
        let client = Arc::new(Mutex::new(MockClient::new()));

        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| {
                Ok(vec![
                    ServiceId::NegativeResponse as u8, // Response ID
                    ServiceId::SecurityAccess as u8,   // Security Access Type
                    nrc::NegativeResponseCode::IncorrectMessageLengthOrInvalidFormat as u8, // NRC
                ])
            });

        let response = security_access_srv
            .send_key(
                client,
                SecurityAccessType(1),
                vec![0xDE, 0xAD, 0xBE, 0xEF],
                None,
            )
            .await
            .unwrap();

        assert!(matches!(
            response,
            UdsResponse::Negative(nrc::NegativeResponseCode::IncorrectMessageLengthOrInvalidFormat)
        ));
    }

    #[tokio::test]
    async fn test_send_key_invalid_key() {
        let security_access_srv = SecurityAccess::new();
        let client = Arc::new(Mutex::new(MockClient::new()));

        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| {
                Ok(vec![
                    ServiceId::NegativeResponse as u8,           // Response ID
                    ServiceId::SecurityAccess as u8,             // Security Access Type
                    nrc::NegativeResponseCode::InvalidKey as u8, // NRC
                ])
            });

        let response = security_access_srv
            .send_key(
                client,
                SecurityAccessType(1),
                vec![0xDE, 0xAD, 0xBE, 0xEF],
                None,
            )
            .await
            .unwrap();

        assert!(matches!(
            response,
            UdsResponse::Negative(nrc::NegativeResponseCode::InvalidKey)
        ));
    }

    #[tokio::test]
    async fn test_send_key_exceed_number_of_attempts() {
        let security_access_srv = SecurityAccess::new();
        let client = Arc::new(Mutex::new(MockClient::new()));

        client
            .lock()
            .await
            .expect_send_request()
            .returning(|_, _, _, _| {
                Ok(vec![
                    ServiceId::NegativeResponse as u8, // Response ID
                    ServiceId::SecurityAccess as u8,   // Security Access Type
                    nrc::NegativeResponseCode::ExceededNumberOfAttempts as u8, // NRC
                ])
            });

        let response = security_access_srv
            .send_key(
                client,
                SecurityAccessType(1),
                vec![0xDE, 0xAD, 0xBE, 0xEF],
                None,
            )
            .await
            .unwrap();

        assert!(matches!(
            response,
            UdsResponse::Negative(nrc::NegativeResponseCode::ExceededNumberOfAttempts)
        ));
    }
}
