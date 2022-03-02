#![no_std]

use core::ffi::c_void;
use optiga_m_sys::cbindings;
use optiga_m_sys::cbindings::{
    hash_data_from_host, hash_data_from_host_t, optiga_crypt_create, optiga_crypt_hash_finalize,
    optiga_crypt_hash_start, optiga_crypt_hash_update, optiga_crypt_t, optiga_hash_context,
    optiga_hash_context_t, optiga_hash_type_OPTIGA_HASH_TYPE_SHA_256, optiga_lib_status_t,
    optiga_util_create, pal_os_event_process, OPTIGA_CRYPT_HOST_DATA, OPTIGA_INSTANCE_ID_0,
    OPTIGA_LIB_BUSY, OPTIGA_LIB_SUCCESS,
};

use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::digital::v2::OutputPin;

unsafe extern "C" fn optiga_util_callback(
    context: *mut c_void,
    return_status: optiga_lib_status_t,
) {
    optiga_lib_status = return_status;
    // if NULL != context {
    //     //callback to upper layer here
    // }
}

static mut optiga_lib_status: optiga_lib_status_t = 0;

pub struct OptigaM {
    lib_util: *mut optiga_crypt_t,
}

#[derive(num_enum::TryFromPrimitive)]
#[repr(u16)]
pub enum CmdError {
    Unspecified = cbindings::OPTIGA_CMD_ERROR,
    InvalidInput = cbindings::OPTIGA_CMD_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_CMD_ERROR_MEMORY_INSUFFICIENT,
}

#[derive(num_enum::TryFromPrimitive)]
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

#[derive(num_enum::TryFromPrimitive)]
#[repr(u16)]
pub enum CryptError {
    Unspecified = cbindings::OPTIGA_CRYPT_ERROR,
    InstanceInUse = cbindings::OPTIGA_CRYPT_ERROR_INSTANCE_IN_USE,
    InvalidInput = cbindings::OPTIGA_CRYPT_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_CRYPT_ERROR_MEMORY_INSUFFICIENT,
}

#[derive(num_enum::TryFromPrimitive)]
#[repr(u16)]
pub enum UtilError {
    InstanceInUse = cbindings::OPTIGA_UTIL_ERROR_INSTANCE_IN_USE,
    InvalidInput = cbindings::OPTIGA_UTIL_ERROR_INVALID_INPUT,
    MemoryInsufficient = cbindings::OPTIGA_UTIL_ERROR_MEMORY_INSUFFICIENT,
}

#[derive(num_enum::TryFromPrimitive)]
#[repr(u16)]
pub enum DeviceError {
    Error = cbindings::OPTIGA_DEVICE_ERROR,
}

#[derive(num_enum::TryFromPrimitive)]
#[repr(u16)]
pub enum Busy {
    Crypt = cbindings::OPTIGA_CRYPT_BUSY as u16,
    // Comms = cbindings::OPTIGA_COMMS_BUSY,
    // Cmd = cbindings::OPTIGA_CMD_BUSY,
    // Util = cbindings::OPTIGA_UTIL_BUSY,
    // Lib = cbindings::OPTIGA_LIB_BUSY,
}

#[derive(num_enum::TryFromPrimitive)]
#[repr(u16)]
pub enum Successes {
    Cmd = cbindings::OPTIGA_CMD_SUCCESS as u16,
    // Comms = cbindings::OPTIGA_COMMS_SUCCESS,
    // Crypt = cbindings::OPTIGA_CRYPT_SUCCESS,
    // Lib = cbindings::OPTIGA_LIB_SUCCESS,
    // Util = cbindings::OPTIGA_UTIL_SUCCESS,
}

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

unsafe fn handleError(returned_status: u16) -> Result<(), OptigaStatus> {
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
    // unsafe fn optiga_wait_while_busy(return_status: u32) {
    //     if OPTIGA_LIB_SUCCESS != return_status {
    //         panic!("Failed at some point while waiting");
    //     }
    //     while OPTIGA_LIB_BUSY == optiga_lib_status.into() {
    //         pal_os_event_process();
    //     }
    //     if OPTIGA_LIB_SUCCESS != return_status {
    //         panic!("Called function failed");
    //     }
    // }

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

        let me_util = unsafe {
            optiga_crypt_create(
                OPTIGA_INSTANCE_ID_0 as u8,
                Some(optiga_util_callback),
                core::ptr::null_mut::<c_void>(),
            )
        };

        if me_util.is_null() {
            panic!("optiga_crypt_create() returned a null pointer");
        }

        OptigaM { lib_util: me_util }
    }

    pub fn sha256(&mut self, bits_to_hash: &[u8]) -> Result<[u8; 32], OptigaStatus> {
        let mut hash_buffer: [u8; 32] = [0; 32];
        // initialize hash context
        let mut hash_context: optiga_hash_context_t = {
            optiga_hash_context {
                context_buffer: unsafe { hash_buffer.as_mut_ptr() },
                context_buffer_length: hash_buffer.len() as u16,
                hash_algo: optiga_hash_type_OPTIGA_HASH_TYPE_SHA_256 as u8,
            }
        };

        let hash_data_context: hash_data_from_host_t = hash_data_from_host {
            buffer: bits_to_hash.as_ptr(),
            length: bits_to_hash.len() as u32,
        };

        if self.lib_util.is_null() {
            panic!("lib_util was dropped and is now a null pointer");
        }

        unsafe {
            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handleError(optiga_crypt_hash_start(
                self.lib_util,
                core::ptr::addr_of_mut!(hash_context),
            ))?;

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handleError(optiga_crypt_hash_update(
                self.lib_util,
                core::ptr::addr_of_mut!(hash_context),
                OPTIGA_CRYPT_HOST_DATA as u8,
                &hash_data_context as *const _ as *const c_void,
            ))?;

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            handleError(optiga_crypt_hash_finalize(
                self.lib_util,
                core::ptr::addr_of_mut!(hash_context),
                hash_buffer.as_mut_ptr(),
            ))?;
        }

        Ok(hash_buffer)
    }
}
