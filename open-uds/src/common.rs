#[macro_export]
macro_rules! try_negative_response {
    ($service_id:expr, $reader:expr) => {
        if $service_id == ServiceId::NegativeResponse {
            let mut nrc_data = [0; 2];
            $reader.read_exact(&mut nrc_data)?;

            return Ok(UdsResponse::Negative(
                crate::nrc::NegativeResponseCode::try_from(nrc_data[1])?,
            ));
        }
    };
}

#[macro_export]
macro_rules! try_match_service_id {
    ($service_id:expr, $expected:expr) => {
        if $service_id != $expected {
            return Err(ClientError::InvalidServiceId($service_id as u8));
        }
    };
}
