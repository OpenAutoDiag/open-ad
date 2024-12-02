//! Implementation of the UDS Tester Present service based on ISO 14229-1:2020
//! section 10.7.
//!
//! This service is used to indicate to a server (or servers) that a client is
//! still connected to the vehicle and that certain diagnostic services and/or
//! communication that have been previously activated are to remain active.
//!
//! This service is used to keep one or multiple servers in a diagnostic session
//! other than the defaultSession. This can either be done by transmitting the
//! TesterPresent request message periodically or in case of the absence of
//! other diagnostic services to prevent the server(s) from automatically
//! returning to the defaultSession.
//!
//! For more, see [`TesterPresent`].

use std::{io::Read, sync::Arc, time::Duration};

use tokio::sync::Mutex;

use crate::{
    try_match_service_id, try_negative_response,
    uds::{self, ClientError, UdsResponse},
};

use super::ServiceId;

/// The TesterPresent (`0x3E`) service implementation.
#[derive(Default)]
pub struct TesterPresent;

impl TesterPresent {
    /// Creates a new instance of the TesterPresent service.
    pub fn new() -> Self {
        Self
    }

    /// Sends a TesterPresent request to the UDS server.
    ///
    /// # Arguments
    ///
    /// * `client` - The UDS client to use for sending the request.
    /// * `timeout` - The maximum time to wait for a response.
    ///
    /// # Returns
    ///
    /// A [`UdsResponse<()>`][UdsResponse] containing the response from the server.
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
    ///     let client = uds::UdsClient::connect(config).await?;
    ///     let client = Arc::new(Mutex::new(client));
    ///
    ///     let test_present_srv = services::tester_present::TesterPresent::new();
    ///     let response = test_present_srv
    ///         .send_tester_present(client, Some(std::time::Duration::from_secs(5)))
    ///         .await?;
    ///
    ///     println!("Tester present response: {:?}", response);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn send_tester_present(
        &self,
        client: Arc<Mutex<dyn uds::Client>>,
        timeout: Option<Duration>,
    ) -> Result<UdsResponse<()>, ClientError> {
        let raw_response = client
            .lock()
            .await
            .send_request(ServiceId::TesterPresent, 0, vec![], timeout)
            .await?;

        let mut reader = std::io::Cursor::new(raw_response);
        let mut response_id = [0u8; 1];
        reader.read_exact(&mut response_id)?;

        let service_id = ServiceId::try_from(response_id[0])?;
        try_negative_response!(service_id, reader);
        try_match_service_id!(service_id, ServiceId::TesterPresent);

        Ok(UdsResponse::Positive(()))
    }
}

/// Macro to run a block of code with a periodic TesterPresent service.
///
/// This macro will run the provided block of code with a periodic TesterPresent
/// service running in the background. The TesterPresent service will be sent
/// every `period` milliseconds.
///
/// # Arguments
///
/// * `client` - The UDS client to use for sending the TesterPresent service.
/// * `period` - The interval in milliseconds to send the TesterPresent service.`
/// * `block` - The block of code to run.
///
/// # Example
/// ```no_run
/// use std::{net::{IpAddr, Ipv4Addr}, sync::Arc};
/// use open_uds::{services, uds::{self, ClientError}};
/// use tokio::sync::Mutex;
///
/// use open_uds::with_periodic_tester;
///
/// #[tokio::main]
/// async fn main() -> Result<(), ClientError> {
///     let config = uds::ClientConfig {
///         source_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
///         source_logical_address: 0x0E00,
///         target_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
///         target_logical_address: 0x000A,
///     };
///     let client = uds::UdsClient::connect(config).await?;
///     let client = Arc::new(Mutex::new(client));
///
///     let _ = with_periodic_tester!(client, 1000, async move {
///         // Do the work here!
///         // Change session, request data, etc.
///         Ok(())
///     });
///
///    Ok(())
/// }
#[macro_export]
macro_rules! with_periodic_tester {
    ($client:expr, $period:expr, $block:expr) => {{
        use std::time::Duration;

        let mut interval = tokio::time::interval(Duration::from_millis($period));
        let client_clone = $client.clone();

        let mut handle = tokio::spawn(async move {
            let tester_present_srv = services::tester_present::TesterPresent::new();
            loop {
                interval.tick().await;

                if let Err(e) = tester_present_srv
                    .send_tester_present(client_clone.clone(), Some(Duration::from_secs(5)))
                    .await
                {
                    eprintln!("Error sending tester present: {:?}", e);
                }
            }
        });

        let result: Result<(), uds::ClientError> = tokio::task::block_in_place(|| $block).await;

        handle.abort();

        result
    }};
}
