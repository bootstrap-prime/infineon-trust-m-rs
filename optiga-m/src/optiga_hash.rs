extern crate alloc;

use crate::call_optiga_func;
use crate::cbindings::{
    self, hash_data_from_host, hash_data_from_host_t, optiga_hash_context, optiga_hash_context_t,
    optiga_hash_type_OPTIGA_HASH_TYPE_SHA_256, OPTIGA_CRYPT_HOST_DATA,
};
use crate::OptigaM;
use alloc::boxed::Box;
use core::ffi::c_void;

pub use digest::DynDigest;

use core::ptr::NonNull;

const OPTIGA_SHA256_CONTEXT_LENGTH: usize =
    cbindings::optiga_hash_context_length_OPTIGA_HASH_CONTEXT_LENGTH_SHA_256 as usize;

/// A wrapper struct for using the SE to compute Sha256 hashes.
pub struct OptigaSha256<'a> {
    periph: &'a mut OptigaM,
    #[allow(dead_code)]
    // this context object must exist and be valid for the attached c library
    hash_context_buffer: Box<[u8; OPTIGA_SHA256_CONTEXT_LENGTH]>,
    hash_context: optiga_hash_context,
    lib_crypt: NonNull<cbindings::optiga_crypt_t>,
}

impl<'a> OptigaSha256<'a> {
    pub fn new(periph: &'a mut OptigaM) -> Self {
        // initialize hash context
        let mut hash_context_buffer: Box<[u8; OPTIGA_SHA256_CONTEXT_LENGTH]> =
            Box::new([0; OPTIGA_SHA256_CONTEXT_LENGTH]);

        let mut hash_context = optiga_hash_context {
            context_buffer: hash_context_buffer.as_mut_ptr(),
            context_buffer_length: hash_context_buffer.len() as u16,
            hash_algo: optiga_hash_type_OPTIGA_HASH_TYPE_SHA_256 as u8,
        };

        let lib_crypt = crate::crypt_create();

        // start hashing operation
        call_optiga_func(|| unsafe {
            cbindings::optiga_crypt_hash_start(lib_crypt.as_ptr(), &mut hash_context)
        })
        .unwrap();

        OptigaSha256 {
            periph,
            hash_context,
            hash_context_buffer,
            lib_crypt,
        }
    }
}

impl<'a> Drop for OptigaSha256<'a> {
    fn drop(&mut self) {
        crate::crypt_destroy(self.lib_crypt);
    }
}

impl<'a> digest::DynDigest for OptigaSha256<'a> {
    fn update(&mut self, data: &[u8]) {
        use core::ptr::addr_of;

        let hash_data_host: hash_data_from_host_t = hash_data_from_host {
            buffer: data.as_ptr(),
            length: data.len() as u32,
        };

        call_optiga_func(|| unsafe {
            cbindings::optiga_crypt_hash_update(
                self.lib_crypt.as_ptr(),
                &mut self.hash_context,
                OPTIGA_CRYPT_HOST_DATA as u8,
                addr_of!(hash_data_host) as *const c_void,
            )
        })
        .unwrap();
    }

    fn finalize_into(mut self, digest: &mut [u8]) -> Result<(), digest::InvalidBufferSize> {
        self.finalize_into_reset(digest)
    }

    fn finalize_into_reset(&mut self, digest: &mut [u8]) -> Result<(), digest::InvalidBufferSize> {
        if digest.len() == 32 {
            call_optiga_func(|| unsafe {
                cbindings::optiga_crypt_hash_finalize(
                    self.lib_crypt.as_ptr(),
                    &mut self.hash_context,
                    digest.as_mut_ptr(),
                )
            })
            .unwrap();

            Ok(())
        } else {
            Err(digest::InvalidBufferSize)
        }
    }

    fn reset(&mut self) {
        let mut digest: [u8; 32] = [0; 32];

        self.finalize_into_reset(&mut digest).unwrap();
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl<'a> digest::HashMarker for OptigaSha256<'a> {}
