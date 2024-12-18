use crate::uds::ClientError;

/// Negative Response Code
///
/// The negative response code is a byte that is sent by the server to indicate
/// that the request was not successful.
#[repr(u8)]
#[derive(Debug, Clone, Copy, strum_macros::Display, Eq, PartialEq)]
pub enum NegativeResponseCode {
    #[strum(serialize = "General reject")]
    GeneralReject = 0x10,
    #[strum(serialize = "Service not supported")]
    ServiceNotSupported = 0x11,
    #[strum(serialize = "Subfunction not supported")]
    SubfunctionNotSupported = 0x12,
    #[strum(serialize = "Incorrect message length or invalid format")]
    IncorrectMessageLengthOrInvalidFormat = 0x13,
    #[strum(serialize = "Response too long")]
    ResponseTooLong = 0x14,
    #[strum(serialize = "Busy, repeat request")]
    BusyRepeatRequest = 0x21,
    #[strum(serialize = "Conditions not correct")]
    ConditionsNotCorrect = 0x22,
    #[strum(serialize = "Request sequence error")]
    RequestSequenceError = 0x24,
    #[strum(serialize = "No response from subnet component")]
    NoResponseFromSubnetComponent = 0x25,
    #[strum(serialize = "Failure prevents execution of requested action")]
    FailurePreventsExecutionOfRequestedAction = 0x26,
    #[strum(serialize = "Request out of range")]
    RequestOutOfRange = 0x31,
    #[strum(serialize = "Security access denied")]
    SecurityAccessDenied = 0x33,
    #[strum(serialize = "Authentication failed")]
    AuthenticationFailed = 0x34,
    #[strum(serialize = "Invalid key")]
    InvalidKey = 0x35,
    #[strum(serialize = "Exceeded number of attempts")]
    ExceededNumberOfAttempts = 0x36,
    #[strum(serialize = "Required time delay not expired")]
    RequiredTimeDelayNotExpired = 0x37,
    #[strum(serialize = "Secure data transmission required")]
    SecureDataTransmissionRequired = 0x38,
    #[strum(serialize = "Secure data transmission not allowed")]
    SecureDataTransmissionNotAllowed = 0x39,
    #[strum(serialize = "Secure data verification failed")]
    SecureDataVerificationFailed = 0x3A,
    #[strum(serialize = "Certificate validation failed, invalid time period")]
    CertificateValidationFailedInvalidTimePeriod = 0x50,
    #[strum(serialize = "Certificate validation failed, invalid signature")]
    CertificateValidationFailedInvalidSignature = 0x51,
    #[strum(serialize = "Certificate validation failed, invalid chain of trust")]
    CertificateValidationFailedInvalidChainOfTrust = 0x52,
    #[strum(serialize = "Certificate validation failed, invalid type")]
    CertificateValidationFailedInvalidType = 0x53,
    #[strum(serialize = "Certificate validation failed, invalid format")]
    CertificateValidationFailedInvalidFormat = 0x54,
    #[strum(serialize = "Certificate validation failed, invalid content")]
    CertificateValidationFailedInvalidContent = 0x55,
    #[strum(serialize = "Certificate validation failed, invalid scope")]
    CertificateValidationFailedInvalidScope = 0x56,
    #[strum(serialize = "Certificate validation failed, invalid certificate")]
    CertificateValidationFailedInvalidCertificate = 0x57,
    #[strum(serialize = "Ownership verification failed")]
    OwnershipVerificationFailed = 0x58,
    #[strum(serialize = "Challenge calculation failed")]
    ChallengeCalculationFailed = 0x59,
    #[strum(serialize = "Setting access right failed")]
    SettingAccessRightFailed = 0x5A,
    #[strum(serialize = "Session key creation/derivation failed")]
    SessionKeyCreationDerivationFailed = 0x5B,
    #[strum(serialize = "Configuration data usage failed")]
    ConfigurationDataUsageFailed = 0x5C,
    #[strum(serialize = "Deauthentication failed")]
    DeauthenticationFailed = 0x5D,
    #[strum(serialize = "Upload download not accepted")]
    UploadDownloadNotAccepted = 0x70,
    #[strum(serialize = "Transfer data suspended")]
    TransferDataSuspended = 0x71,
    #[strum(serialize = "General programming failure")]
    GeneralProgrammingFailure = 0x72,
    #[strum(serialize = "Wrong block sequence number")]
    WrongBlockSequenceNumber = 0x73,
    #[strum(serialize = "Request correctly received, response pending")]
    RequestCorrectlyReceivedResponsePending = 0x78,
    #[strum(serialize = "Subfunction not supported in active session")]
    SubfunctionNotSupportedInActiveSession = 0x7E,
    #[strum(serialize = "Service not supported in active session")]
    ServiceNotSupportedInActiveSession = 0x7F,
    #[strum(serialize = "RPM too high")]
    RPMTooHigh = 0x81,
    #[strum(serialize = "RPM too low")]
    RPMTooLow = 0x82,
    #[strum(serialize = "Engine is running")]
    EngineIsRunning = 0x83,
    #[strum(serialize = "Engine is not running")]
    EngineIsNotRunning = 0x84,
    #[strum(serialize = "Engine run time too low")]
    EngineRunTimeTooLow = 0x85,
    #[strum(serialize = "Temperature too high")]
    TemperatureTooHigh = 0x86,
    #[strum(serialize = "Temperature too low")]
    TemperatureTooLow = 0x87,
    #[strum(serialize = "Vehicle speed too high")]
    VehicleSpeedTooHigh = 0x88,
    #[strum(serialize = "Vehicle speed too low")]
    VehicleSpeedTooLow = 0x89,
    #[strum(serialize = "Throttle/pedal too high")]
    ThrottlePedalTooHigh = 0x8A,
    #[strum(serialize = "Throttle/pedal too low")]
    ThrottlePedalTooLow = 0x8B,
    #[strum(serialize = "Transmission range not in neutral")]
    TransmissionRangeNotInNeutral = 0x8C,
    #[strum(serialize = "Transmission range not in gear")]
    TransmissionRangeNotInGear = 0x8D,
    #[strum(serialize = "Brake switch not closed")]
    BrakeSwitchNotClosed = 0x8F,
    #[strum(serialize = "Shifter lever not in park")]
    ShifterLeverNotInPark = 0x90,
    #[strum(serialize = "Torque converter clutch locked")]
    TorqueConverterClutchLocked = 0x91,
    #[strum(serialize = "Voltage too high")]
    VoltageTooHigh = 0x92,
    #[strum(serialize = "Voltage too low")]
    VoltageTooLow = 0x93,
    #[strum(serialize = "Resource temporary unavailable")]
    ResourceTemporaryUnavailable = 0x94,
}

impl TryFrom<u8> for NegativeResponseCode {
    type Error = ClientError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x10 => Ok(NegativeResponseCode::GeneralReject),
            0x11 => Ok(NegativeResponseCode::ServiceNotSupported),
            0x12 => Ok(NegativeResponseCode::SubfunctionNotSupported),
            0x13 => Ok(NegativeResponseCode::IncorrectMessageLengthOrInvalidFormat),
            0x14 => Ok(NegativeResponseCode::ResponseTooLong),
            0x21 => Ok(NegativeResponseCode::BusyRepeatRequest),
            0x22 => Ok(NegativeResponseCode::ConditionsNotCorrect),
            0x24 => Ok(NegativeResponseCode::RequestSequenceError),
            0x25 => Ok(NegativeResponseCode::NoResponseFromSubnetComponent),
            0x26 => Ok(NegativeResponseCode::FailurePreventsExecutionOfRequestedAction),
            0x31 => Ok(NegativeResponseCode::RequestOutOfRange),
            0x33 => Ok(NegativeResponseCode::SecurityAccessDenied),
            0x34 => Ok(NegativeResponseCode::AuthenticationFailed),
            0x35 => Ok(NegativeResponseCode::InvalidKey),
            0x36 => Ok(NegativeResponseCode::ExceededNumberOfAttempts),
            0x37 => Ok(NegativeResponseCode::RequiredTimeDelayNotExpired),
            0x38 => Ok(NegativeResponseCode::SecureDataTransmissionRequired),
            0x39 => Ok(NegativeResponseCode::SecureDataTransmissionNotAllowed),
            0x3A => Ok(NegativeResponseCode::SecureDataVerificationFailed),
            0x50 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidTimePeriod),
            0x51 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidSignature),
            0x52 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidChainOfTrust),
            0x53 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidType),
            0x54 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidFormat),
            0x55 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidContent),
            0x56 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidScope),
            0x57 => Ok(NegativeResponseCode::CertificateValidationFailedInvalidCertificate),
            0x58 => Ok(NegativeResponseCode::OwnershipVerificationFailed),
            0x59 => Ok(NegativeResponseCode::ChallengeCalculationFailed),
            0x5A => Ok(NegativeResponseCode::SettingAccessRightFailed),
            0x5B => Ok(NegativeResponseCode::SessionKeyCreationDerivationFailed),
            0x5C => Ok(NegativeResponseCode::ConfigurationDataUsageFailed),
            0x5D => Ok(NegativeResponseCode::DeauthenticationFailed),
            0x70 => Ok(NegativeResponseCode::UploadDownloadNotAccepted),
            0x71 => Ok(NegativeResponseCode::TransferDataSuspended),
            0x72 => Ok(NegativeResponseCode::GeneralProgrammingFailure),
            0x73 => Ok(NegativeResponseCode::WrongBlockSequenceNumber),
            0x78 => Ok(NegativeResponseCode::RequestCorrectlyReceivedResponsePending),
            0x7E => Ok(NegativeResponseCode::SubfunctionNotSupportedInActiveSession),
            0x7F => Ok(NegativeResponseCode::ServiceNotSupportedInActiveSession),
            0x81 => Ok(NegativeResponseCode::RPMTooHigh),
            0x82 => Ok(NegativeResponseCode::RPMTooLow),
            0x83 => Ok(NegativeResponseCode::EngineIsRunning),
            0x84 => Ok(NegativeResponseCode::EngineIsNotRunning),
            0x85 => Ok(NegativeResponseCode::EngineRunTimeTooLow),
            0x86 => Ok(NegativeResponseCode::TemperatureTooHigh),
            0x87 => Ok(NegativeResponseCode::TemperatureTooLow),
            0x88 => Ok(NegativeResponseCode::VehicleSpeedTooHigh),
            0x89 => Ok(NegativeResponseCode::VehicleSpeedTooLow),
            0x8A => Ok(NegativeResponseCode::ThrottlePedalTooHigh),
            0x8B => Ok(NegativeResponseCode::ThrottlePedalTooLow),
            0x8C => Ok(NegativeResponseCode::TransmissionRangeNotInNeutral),
            0x8D => Ok(NegativeResponseCode::TransmissionRangeNotInGear),
            0x8F => Ok(NegativeResponseCode::BrakeSwitchNotClosed),
            0x90 => Ok(NegativeResponseCode::ShifterLeverNotInPark),
            0x91 => Ok(NegativeResponseCode::TorqueConverterClutchLocked),
            0x92 => Ok(NegativeResponseCode::VoltageTooHigh),
            0x93 => Ok(NegativeResponseCode::VoltageTooLow),
            0x94 => Ok(NegativeResponseCode::ResourceTemporaryUnavailable),
            _ => Err(ClientError::InvalidResponseCode(value)),
        }
    }
}
