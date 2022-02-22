#![no_std]

use core::ffi::c_void;
use optiga_m_sys::cbindings::{
    hash_data_from_host, hash_data_from_host_t, optiga_crypt_create, optiga_crypt_hash_finalize,
    optiga_crypt_hash_start, optiga_crypt_hash_update, optiga_crypt_t, optiga_hash_context,
    optiga_hash_context_t, optiga_hash_type_OPTIGA_HASH_TYPE_SHA_256, optiga_lib_status_t,
    optiga_util_create, OPTIGA_CRYPT_HOST_DATA, OPTIGA_INSTANCE_ID_0, OPTIGA_LIB_BUSY,
};

use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::digital::v2::OutputPin;

unsafe extern "C" fn optiga_util_callback(
    context: *mut c_void,
    return_status: optiga_lib_status_t,
) {
    unsafe {
        optiga_lib_status = return_status;
    }
    // if NULL != context {
    //     //callback to upper layer here
    // }
}

static mut optiga_lib_status: optiga_lib_status_t = 0;

pub struct OptigaM {
    lib_util: *mut optiga_crypt_t,
}

impl OptigaM {
    fn new<RSTPin: 'static, VCCPin: 'static, I2CPin: 'static>(
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

        OptigaTrustM::setup_new(rst, pwr, i2c);

        let mut me_util = unsafe {
            optiga_crypt_create(
                OPTIGA_INSTANCE_ID_0 as u8,
                Some(optiga_util_callback),
                core::ptr::null_mut::<c_void>(),
            )
        };

        OptigaM { lib_util: me_util }
    }

    fn sha256(&mut self, bits_to_hash: &[u8]) {
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

        unsafe {
            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            optiga_crypt_hash_start(self.lib_util, core::ptr::addr_of_mut!(hash_context));

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            optiga_crypt_hash_update(
                self.lib_util,
                core::ptr::addr_of_mut!(hash_context),
                OPTIGA_CRYPT_HOST_DATA as u8,
                &hash_data_context as *const _ as *const c_void,
            );

            optiga_lib_status = OPTIGA_LIB_BUSY as u16;
            optiga_crypt_hash_finalize(
                self.lib_util,
                core::ptr::addr_of_mut!(hash_context),
                hash_buffer.as_mut_ptr(),
            );
        }
    }
}
