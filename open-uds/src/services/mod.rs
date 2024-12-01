pub mod ecu_reset;
pub mod security_access;
pub mod tester_present;

use crate::uds::ClientError;

/// Service identifiers per ISO 14229-1:2020, table 23.
#[repr(u8)]
#[derive(Debug, Clone, Copy, strum_macros::Display, PartialEq, Eq)]
pub enum ServiceId {
    DiagnosticSessionControl = 0x10,
    ECUReset = 0x11,
    SecurityAccess = 0x27,
    CommunicationControl = 0x28,
    TesterPresent = 0x3E,
    Authentication = 0x29,
    SecuredDataTransmission = 0x84,
    ControlDTCSetting = 0x85,
    ResponseOnEvent = 0x86,
    LinkControl = 0x87,
    ReadDataByIdentifier = 0x22,
    ReadMemoryByAddress = 0x23,
    ReadScalingDataByIdentifier = 0x24,
    ReadDataByPeriodicIdentifier = 0x2A,
    DynamicallyDefineDataIdentifier = 0x2C,
    WriteDataByIdentifier = 0x2E,
    WriteMemoryByAddress = 0x3D,
    ClearDiagnosticInformation = 0x14,
    ReadDTCInformation = 0x19,
    InputOutputControlByIdentifier = 0x2F,
    RoutineControl = 0x31,
    RequestDownload = 0x34,
    RequestUpload = 0x35,
    TransferData = 0x36,
    RequestTransfer = 0x37,
    RequestFileTransfer = 0x38,

    // Response service with NegativeResponseCode
    NegativeResponse = 0x47,
}

impl TryFrom<u8> for ServiceId {
    type Error = ClientError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x11 | 0x51 => Ok(ServiceId::ECUReset),
            0x3E | 0x7E => Ok(ServiceId::TesterPresent),
            0x27 | 0x67 => Ok(ServiceId::SecurityAccess),
            0x47 => Ok(ServiceId::NegativeResponse),
            _ => Err(ClientError::InvalidServiceId(value)),
        }
    }
}
