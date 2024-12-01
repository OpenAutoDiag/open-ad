use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use tokio::sync::Mutex;

use open_uds::{
    services::{self, security_access::SecurityAccessType},
    uds::{self, ClientError},
    with_periodic_tester,
};

#[tokio::main]
async fn main() -> Result<(), ClientError> {
    let config = uds::ClientConfig {
        source_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        source_logical_address: 0x0E00,
        target_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        target_logical_address: 0x000A,
    };
    let client = uds::UdsClient::connect(config).await?;
    let client = Arc::new(Mutex::new(client));

    let _ = with_periodic_tester!(client, 1000, async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let sa = services::security_access::SecurityAccess::new();

        let response = sa
            .request_seed(client.clone(), SecurityAccessType(1), None, None)
            .await?;

        let mut seed = match response {
            uds::UdsResponse::Positive(seed) => seed,
            uds::UdsResponse::Negative(nrc) => {
                println!("Seed request failed: {:?}", nrc);
                return Ok(());
            }
        };

        let key = seed
            .0
            .iter_mut()
            .map(|byte| byte.wrapping_add(1))
            .collect::<Vec<_>>();

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let response = sa
            .send_key(client.clone(), SecurityAccessType(1), key, None)
            .await?;

        println!("{:?}", response);

        let ecu_reset_srv = services::ecu_reset::EcuReset::new();

        let response = ecu_reset_srv
            .reset(
                client.clone(),
                services::ecu_reset::ResetType::HardReset,
                None,
            )
            .await?;

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        println!("{:?}", response);

        Ok(())
    });

    Ok(())
}
