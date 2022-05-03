#![cfg_attr(not(test), no_std)]

use core::ffi::c_void;
use core::fmt::Debug;
use core::ptr::NonNull;
use optiga_m_sys::cbindings::{self, optiga_util_open_application, optiga_util_t};
use optiga_m_sys::cbindings::{
    hash_data_from_host, hash_data_from_host_t, optiga_crypt_create, optiga_crypt_hash_finalize,
    optiga_crypt_hash_start, optiga_crypt_hash_update, optiga_crypt_t, optiga_hash_context,
    optiga_hash_context_t, optiga_hash_type_OPTIGA_HASH_TYPE_SHA_256, optiga_lib_status_t,
    optiga_util_create, OPTIGA_CRYPT_HOST_DATA, OPTIGA_INSTANCE_ID_0, OPTIGA_LIB_BUSY,
    OPTIGA_LIB_SUCCESS,
};
use optiga_m_sys::pal_os_event::pal_os_event_process;

use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::digital::v2::OutputPin;

unsafe extern "C" fn optiga_util_callback(
    _context: *mut c_void,
    return_status: optiga_lib_status_t,
) {
    optiga_lib_status = return_status;
}

static mut optiga_lib_status: optiga_lib_status_t = 0;

pub struct OptigaM {
    lib_crypt: NonNull<optiga_crypt_t>,
    lib_util: NonNull<optiga_util_t>,
}

#[derive(num_enum::TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum CmdError {
    Unspecified = cbindings::OPTIGA_CMD_ERROR,
    InvalidInput = cbindings::OPTIGA_CMD_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_CMD_ERROR_MEMORY_INSUFFICIENT,
}

#[derive(num_enum::TryFromPrimitive, Debug)]
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

#[derive(num_enum::TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum CryptError {
    Unspecified = cbindings::OPTIGA_CRYPT_ERROR,
    InstanceInUse = cbindings::OPTIGA_CRYPT_ERROR_INSTANCE_IN_USE,
    InvalidInput = cbindings::OPTIGA_CRYPT_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_CRYPT_ERROR_MEMORY_INSUFFICIENT,
}

#[derive(num_enum::TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum UtilError {
    Unspecified = cbindings::OPTIGA_UTIL_ERROR,
    InstanceInUse = cbindings::OPTIGA_UTIL_ERROR_INSTANCE_IN_USE,
    InvalidInput = cbindings::OPTIGA_UTIL_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_UTIL_ERROR_MEMORY_INSUFFICIENT,
}

#[derive(num_enum::TryFromPrimitive, Debug)]
#[repr(u16)]
/// Possible errors returned by the device, defined in https://github.com/Infineon/optiga-trust-m/wiki/Device-Error-Codes
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
    InvalidParameterInDataField = 0x8005,
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

#[derive(num_enum::TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum Busy {
    Crypt = cbindings::OPTIGA_CRYPT_BUSY as u16,
    // Comms = cbindings::OPTIGA_COMMS_BUSY,
    // Cmd = cbindings::OPTIGA_CMD_BUSY,
    // Util = cbindings::OPTIGA_UTIL_BUSY,
    // Lib = cbindings::OPTIGA_LIB_BUSY,
}

#[derive(num_enum::TryFromPrimitive, Debug)]
#[repr(u16)]
pub enum Successes {
    Cmd = cbindings::OPTIGA_CMD_SUCCESS as u16,
    // despite the name, apparenly this macro by itself is a success
    Device = cbindings::OPTIGA_DEVICE_ERROR as u16,
    // Comms = cbindings::OPTIGA_COMMS_SUCCESS,
    // Crypt = cbindings::OPTIGA_CRYPT_SUCCESS,
    // Lib = cbindings::OPTIGA_LIB_SUCCESS,
    // Util = cbindings::OPTIGA_UTIL_SUCCESS,
}

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

impl From<u16> for OptigaStatus {
    fn from(numeric_error: u16) -> OptigaStatus {
        use core::convert::TryFrom;

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

unsafe fn handle_error(returned_status: u16) -> Result<(), OptigaStatus> {
    match returned_status.into() {
        OptigaStatus::Success(_) => {
            #[cfg(not(any(test, feature = "tester")))]
            defmt::trace!("processing");
            while let OptigaStatus::Busy(_) = optiga_lib_status.into() {
                pal_os_event_process();
            }
            #[cfg(not(any(test, feature = "tester")))]
            defmt::trace!("processed");

            match optiga_lib_status.into() {
                OptigaStatus::Success(_) => Ok(()),
                e => Err(e),
            }
        }
        e => Err(e),
    }
}

impl OptigaM {
    pub fn new<RSTPin: 'static, VCCPin: 'static, I2CPin: 'static>(
        rst: RSTPin,
        pwr: VCCPin,
        i2c: I2CPin,
    ) -> OptigaM
    where
        RSTPin: OutputPin,
        VCCPin: OutputPin,
        I2CPin: Write + Read,
        <I2CPin as Write>::Error: Debug,
        <I2CPin as Read>::Error: Debug,
    {
        use optiga_m_sys::OptigaTrustM;

        unsafe {
            OptigaTrustM::setup_new(rst, pwr, i2c);
        }

        #[cfg(not(test))]
        defmt::trace!("periph setup");

        let lib_util = unsafe {
            let lib_util = NonNull::new(optiga_util_create(
                OPTIGA_INSTANCE_ID_0,
                Some(optiga_util_callback),
                core::ptr::null_mut(),
            ))
            .expect("optiga_util_create() returned a null pointer");

            #[cfg(not(test))]
            defmt::trace!("lib util created");

            lib_util
        };

        let lib_crypt = unsafe {
            NonNull::new(optiga_crypt_create(
                OPTIGA_INSTANCE_ID_0 as u8,
                Some(optiga_util_callback),
                core::ptr::null_mut(),
            ))
            .expect("optiga_crypt_create() returned a null pointer")
        };

        unsafe {
            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handle_error(optiga_util_open_application(lib_util.as_ptr(), false as u8))
                .expect("was unable to initialize utility");
        }

        OptigaM {
            lib_util,
            lib_crypt,
        }
    }

    pub fn test_optiga_communication(&mut self) -> Result<(), OptigaStatus> {
        let mut transmit_buffer: [u8; 1] = [0x82];
        let mut recv_buffer: [u8; 4] = [0; 4];

        let optiga_pal_i2c_context_0: cbindings::pal_i2c_t = cbindings::pal_i2c {
            p_i2c_hw_config: core::ptr::null_mut(),
            p_upper_layer_ctx: core::ptr::null_mut(),
            upper_layer_event_handler: optiga_util_callback as *mut c_void,
            slave_address: 0x30,
        };

        let mut pal_return_status: u16 = cbindings::PAL_I2C_EVENT_SUCCESS.into();

        unsafe {
            while cbindings::PAL_I2C_EVENT_SUCCESS as u16 != optiga_lib_status {
                optiga_lib_status = cbindings::PAL_I2C_EVENT_BUSY.into();
                pal_return_status = cbindings::pal_i2c_write(
                    &optiga_pal_i2c_context_0,
                    transmit_buffer.as_mut_ptr(),
                    transmit_buffer.len() as u16,
                );

                if cbindings::PAL_STATUS_FAILURE as u16 == optiga_lib_status {
                    break;
                }
            }
        }

        unsafe {
            while cbindings::PAL_I2C_EVENT_SUCCESS as u16 != optiga_lib_status {
                optiga_lib_status = cbindings::PAL_I2C_EVENT_BUSY.into();
                pal_return_status = cbindings::pal_i2c_read(
                    &optiga_pal_i2c_context_0,
                    recv_buffer.as_mut_ptr(),
                    recv_buffer.len() as u16,
                );

                if cbindings::PAL_STATUS_FAILURE as u16 == optiga_lib_status {
                    break;
                }
            }
        }

        unsafe { handle_error(pal_return_status) }
    }

    pub fn sha256(&mut self, bits_to_hash: &[u8]) -> Result<[u8; 32], OptigaStatus> {
        let mut hash_buffer: [u8; 32] = [0; 32];
        // initialize hash context
        let mut hash_context: optiga_hash_context_t = {
            optiga_hash_context {
                context_buffer: hash_buffer.as_mut_ptr(),
                context_buffer_length: hash_buffer.len() as u16,
                hash_algo: optiga_hash_type_OPTIGA_HASH_TYPE_SHA_256 as u8,
            }
        };

        let hash_data_context: hash_data_from_host_t = hash_data_from_host {
            buffer: bits_to_hash.as_ptr(),
            length: bits_to_hash.len() as u32,
        };

        use core::ptr::addr_of_mut;

        unsafe {
            #[cfg(not(test))]
            defmt::trace!("starting hash");

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handle_error(optiga_crypt_hash_start(
                self.lib_crypt.as_ptr(),
                addr_of_mut!(hash_context),
            ))?;

            #[cfg(not(test))]
            defmt::trace!("started hash");

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handle_error(optiga_crypt_hash_update(
                self.lib_crypt.as_ptr(),
                addr_of_mut!(hash_context),
                OPTIGA_CRYPT_HOST_DATA as u8,
                &hash_data_context as *const _ as *const c_void,
            ))?;

            #[cfg(not(test))]
            defmt::trace!("updated hash with data");

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handle_error(optiga_crypt_hash_finalize(
                self.lib_crypt.as_ptr(),
                addr_of_mut!(hash_context),
                hash_buffer.as_mut_ptr(),
            ))?;

            #[cfg(not(test))]
            defmt::trace!("finalized hash, returning");
        }

        Ok(hash_buffer)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn dont_segfault() {
        use crate::OptigaM;
        use embedded_hal_mock::i2c::Transaction as I2CTransaction;
        use embedded_hal_mock::{i2c::Mock as I2CMock, pin::Mock as PinMock};

        println!("hi");

        let mut rstpin = PinMock::new(&[]);
        let mut vccpin = rstpin.clone();
        let mut i2cpin = I2CMock::new(&[
            I2CTransaction::write(48, vec![132]),
            I2CTransaction::read(48, vec![0, 0, 1, 144]),
            I2CTransaction::write(48, vec![129, 1, 21]),
            I2CTransaction::write(48, vec![129]),
            I2CTransaction::read(48, vec![1, 21]),
            I2CTransaction::write(
                48,
                vec![
                    128, 3, 0, 21, 0, 240, 0, 0, 16, 210, 118, 0, 0, 4, 71, 101, 110, 65, 117, 116,
                    104, 65, 112, 112, 108, 201, 182,
                ],
            ),
            I2CTransaction::write(48, vec![130]),
        ]);

        let mut device = OptigaM::new(rstpin, vccpin, i2cpin);

        let optiga_result = device.sha256(&[0, 1, 2, 3]).unwrap();
    }
}
