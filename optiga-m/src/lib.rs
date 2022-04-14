#![no_std]

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
pub enum DeviceError {
    Error = cbindings::OPTIGA_DEVICE_ERROR,
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
        match numeric_error.try_into() {
            Ok(e) => e,
            Err(_e) => OptigaStatus::Unknown(numeric_error),
        }
    }
}

unsafe fn handle_error(returned_status: u16) -> Result<(), OptigaStatus> {
    match returned_status.into() {
        OptigaStatus::Success(_) => Ok(()),
        OptigaStatus::Busy(_) => loop {
            // poll the "async" stack until we get something that isn't busy
            match optiga_lib_status.into() {
                OptigaStatus::Busy(_) => pal_os_event_process(),
                OptigaStatus::Success(_) => break Ok(()),
                e => break Err(e),
            }
        },
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
    {
        use optiga_m_sys::OptigaTrustM;

        unsafe {
            OptigaTrustM::setup_new(rst, pwr, i2c);
        }

        let lib_util = unsafe {
            let lib_util = NonNull::new(optiga_util_create(
                OPTIGA_INSTANCE_ID_0,
                Some(optiga_util_callback),
                core::ptr::null_mut(),
            ))
            .expect("optiga_util_create() returned a null pointer");

            handle_error(optiga_util_open_application(lib_util.as_ptr(), false as u8))
                .expect("was unable to initialize utility");

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

        OptigaM {
            lib_util,
            lib_crypt,
        }
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
            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handle_error(optiga_crypt_hash_start(
                self.lib_crypt.as_ptr(),
                addr_of_mut!(hash_context),
            ))?;

            defmt::trace!("started hash");

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handle_error(optiga_crypt_hash_update(
                self.lib_crypt.as_ptr(),
                addr_of_mut!(hash_context),
                OPTIGA_CRYPT_HOST_DATA as u8,
                &hash_data_context as *const _ as *const c_void,
            ))?;

            defmt::trace!("updated hash with data");

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handle_error(optiga_crypt_hash_finalize(
                self.lib_crypt.as_ptr(),
                addr_of_mut!(hash_context),
                hash_buffer.as_mut_ptr(),
            ))?;

            defmt::trace!("finalized hash, returning");
        }

        Ok(hash_buffer)
    }
}
