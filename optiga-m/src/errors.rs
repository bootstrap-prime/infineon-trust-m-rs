use crate::cbindings;
use crate::{optiga_lib_status_t, OPTIGA_LIB_BUSY};
use core::ffi::c_void;
use optiga_m_sys::pal_os_event::pal_os_event_process;

/// Possible errors in commanding the secure element.
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug)]
#[repr(u16)]
pub enum CmdError {
    Unspecified = cbindings::OPTIGA_CMD_ERROR,
    InvalidInput = cbindings::OPTIGA_CMD_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_CMD_ERROR_MEMORY_INSUFFICIENT,
}

/// Possible communication errors between the host and the secure element.
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug)]
#[repr(u16)]
pub enum CommsError {
    Unspecified = cbindings::OPTIGA_COMMS_ERROR,
    Fatal = cbindings::OPTIGA_COMMS_ERROR_FATAL,
    Handshake = cbindings::OPTIGA_COMMS_ERROR_HANDSHAKE,
    InvalidInput = cbindings::OPTIGA_COMMS_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_COMMS_ERROR_MEMORY_INSUFFICIENT,
    SessionError = cbindings::OPTIGA_COMMS_ERROR_SESSION,
    StackMemory = cbindings::OPTIGA_COMMS_ERROR_STACK_MEMORY,
}

/// Possible errors that can occur when performing cryptography code.
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug)]
#[repr(u16)]
pub enum CryptError {
    Unspecified = cbindings::OPTIGA_CRYPT_ERROR,
    InstanceInUse = cbindings::OPTIGA_CRYPT_ERROR_INSTANCE_IN_USE,
    InvalidInput = cbindings::OPTIGA_CRYPT_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_CRYPT_ERROR_MEMORY_INSUFFICIENT,
}

/// Possible pure library error codes returned by the internally bound optiga-trust-m host library.
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug)]
#[repr(u16)]
pub enum UtilError {
    Unspecified = cbindings::OPTIGA_UTIL_ERROR,
    InstanceInUse = cbindings::OPTIGA_UTIL_ERROR_INSTANCE_IN_USE,
    InvalidInput = cbindings::OPTIGA_UTIL_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_UTIL_ERROR_MEMORY_INSUFFICIENT,
}

/// Possible errors returned by the device, defined in <https://github.com/Infineon/optiga-trust-m/wiki/Device-Error-Codes>
#[allow(dead_code)]
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug)]
#[repr(u16)]
pub enum DeviceError {
    ///Invalid OID
    InvalidOID = 0x8001,
    ///Invalid Password
    InvalidPassword = 0x8002,
    ///Invalid Param field in command
    InvalidParamField = 0x8003,
    ///Invalid Length field in command
    InvalidLenField = 0x8004,
    ///Invalid parameter in command data field
    InvalidParameterInCmdDataField = 0x8005,
    ///Internal process error
    InternalProcessError = 0x8006,
    ///Access conditions are not satisfied
    AccessConditionsNotSatisfied = 0x8007,
    ///The sum of offset and data provided (offset + data length) exceeds the max length of the data object
    DataObjectBoundaryExceeded = 0x8008,
    ///Metadata truncation error
    MetadataTruncationError = 0x8009,
    ///Invalid command field
    InvalidCmdField = 0x800A,
    ///Command or message out of sequence.
    /// Command out of sequence means that the command which expected to use certain resources are not available or not started at chip
    /// e.g. invoking the optiga_crypt_tls_prf_sha256() function (which is using session) before invoking the optiga_crypt_ecdh() function.
    /// Another example is a usage of the optiga_crypt_ecdh() and optiga_crypt_tls_prf_sha256() functions in the row using the Session OID
    /// without optiga_crypt_ecc_generate_keypair(), this leads to failure "of out of sequence" due to a lack of private key in Session OID slot
    CmdOutOfSequence = 0x800B,
    ///due to termination state of the application or due to Application closed
    CmdNotAvailable = 0x800C,
    ///Insufficient memory to process the command APDU
    InsufficientMemoryBuffer = 0x800D,
    ///Counter value crossed the threshold limit and further counting is denied.
    CounterThresholdLimitExceeded = 0x800E,
    ///The Manifest version provided is not supported or the Payload Version in Manifest has MSB set (Invalid Flag=1).
    /// Invalid or un-supported manifest values or formats including CBOR parsing errors.
    InvalidManifest = 0x800F,
    ///The Payload Version provided in the Manifest is not greater than the version of the target object
    /// or the last update was interrupted and the restarted/retried update has not the same version
    InvalidOrWrongPayloadVersion = 0x8010,
    ///Illegal parameters in (D)TLS Handshake message, either in header or data.
    InvalidHandshakeMessage = 0x8021,
    ///Protocol or data structure version mismatch (e.g. X.509 Version, ...).
    VersionMismatch = 0x8022,
    ///Cipher suite mismatch between client and server.
    InsufficientOrUnsupportedCipherSuite = 0x8023,
    ///An unsupported extension found in the message. Unsupported keyusage/Algorithm extension/identifier for the usage of Private key
    UnsupportedExtensionOrIdentifier = 0x8024,
    ///The Trust Anchor is either not loaded or the loaded Trust Anchor is invalid e.g. not well formed X.509 certificate, public key missing, ...).
    InvalidTrustAnchor = 0x8026,
    ///The Trust Anchor loaded at OPTIGA Trust is expired.
    TrustAnchorExpired = 0x8027,
    ///The cryptographic algorithms specified in Trust Anchor loaded are not supported by OPTIGA Trust.
    UnsupportedTrustAnchor = 0x8028,
    ///Invalid certificate(s) in certificate message with the following reasons.
    InvalidCertificateFormat = 0x8029,
    ///At least one cryptographic algorithm specified in the certificate is not supported (e.g. hash or sign algorithms).
    UnsupportedCertificateAlgorithm = 0x802A,
    ///The certificate or at least one certificate in a certificate chain received is expired.
    CertificateExpired = 0x802B,
    ///Signature verification failure.
    SignatureVerificationFailure = 0x802C,
    ///Message Integrity validation failure (e.g. during CCM decryption).
    IntegrityValidationFailure = 0x802D,
    ///Decryption Failure.
    DecryptionFailure = 0x802E,
}

/// Possible busy codes returned by the internally bound optiga-trust-m host library.
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug)]
#[repr(u16)]
pub enum Busy {
    Busy = cbindings::OPTIGA_CRYPT_BUSY as u16,
}

/// Possible success codes returned by the internally bound optiga-trust-m host library.
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Debug)]
#[repr(u16)]
pub enum Successes {
    Cmd = cbindings::OPTIGA_CMD_SUCCESS as u16,
    // despite the name, apparently this macro by itself is a success
    Device = cbindings::OPTIGA_DEVICE_ERROR as u16,
}

/// All possible errors that can be returned by this crate.
#[derive(Debug)]
#[repr(u16)]
pub enum OptigaStatus {
    Unknown(u16),
    Busy(Busy),
    CmdError(CmdError),
    CommsError(CommsError),
    CryptError(CryptError),
    UtilError(UtilError),
    DeviceError(DeviceError),
    Success(Successes),
}

impl From<OptigaStatus> for u16 {
    fn from(error: OptigaStatus) -> u16 {
        use OptigaStatus::*;

        match error {
            Unknown(e) => e,
            Busy(e) => e.into(),
            CmdError(e) => e.into(),
            CommsError(e) => e.into(),
            CryptError(e) => e.into(),
            UtilError(e) => e.into(),
            DeviceError(e) => e.into(),
            Success(e) => e.into(),
        }
    }
}

impl From<u16> for OptigaStatus {
    fn from(numeric_error: u16) -> OptigaStatus {
        use OptigaStatus::*;
        if let Ok(e) = numeric_error.try_into() {
            Busy(e)
        } else if let Ok(e) = numeric_error.try_into() {
            Success(e)
        } else if let Ok(e) = numeric_error.try_into() {
            CmdError(e)
        } else if let Ok(e) = numeric_error.try_into() {
            CommsError(e)
        } else if let Ok(e) = numeric_error.try_into() {
            CryptError(e)
        } else if let Ok(e) = numeric_error.try_into() {
            UtilError(e)
        } else if let Ok(e) = numeric_error.try_into() {
            DeviceError(e)
        } else {
            Unknown(numeric_error)
        }
    }
}

pub unsafe fn handle_error(returned_status: u16) -> Result<(), OptigaStatus> {
    match returned_status.into() {
        OptigaStatus::Success(_) => {
            #[cfg(not(any(test, feature = "tester")))]
            defmt::trace!("processing");
            while let OptigaStatus::Busy(_) = OPTIGA_LIB_STATUS.into() {
                pal_os_event_process();
            }
            #[cfg(not(any(test, feature = "tester")))]
            defmt::trace!("processed");

            match OPTIGA_LIB_STATUS.into() {
                OptigaStatus::Success(_) => {
                    #[cfg(not(any(test, feature = "tester")))]
                    defmt::trace!("returned success");
                    Ok(())
                }
                e => {
                    extern crate alloc;
                    #[cfg(not(any(test, feature = "tester")))]
                    defmt::trace!(
                        "did not return success, err {}",
                        alloc::format!("{:?}", e).as_str()
                    );

                    Err(e)
                }
            }
        }
        e => {
            extern crate alloc;
            #[cfg(not(any(test, feature = "tester")))]
            defmt::trace!(
                "did not return success, err {}",
                alloc::format!("{:?}", e).as_str()
            );
            Err(e)
        }
    }
}

pub fn call_optiga_func<T: FnOnce() -> u16>(returned_process: T) -> Result<(), OptigaStatus> {
    unsafe {
        OPTIGA_LIB_STATUS = OPTIGA_LIB_BUSY as u16;
    }

    unsafe {
        handle_error(returned_process())?;
    }

    Ok(())
}

pub unsafe extern "C" fn optiga_util_callback(
    _context: *mut c_void,
    return_status: optiga_lib_status_t,
) {
    OPTIGA_LIB_STATUS = return_status;
}

pub static mut OPTIGA_LIB_STATUS: optiga_lib_status_t = 0;
