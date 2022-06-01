#![cfg_attr(not(test), no_std)]

mod errors;
mod optiga_hash;
mod optiga_rand;
mod optiga_sign;

use errors::{call_optiga_func, handle_error, optiga_util_callback};
pub use errors::{CmdError, CommsError, CryptError, DeviceError, OptigaStatus, UtilError};
pub use optiga_hash::*;
pub use optiga_sign::*;

use core::ffi::c_void;
use core::fmt::Debug;
use core::ptr::NonNull;
use optiga_m_sys::cbindings::{self, optiga_util_open_application, optiga_util_t};
use optiga_m_sys::cbindings::{
    optiga_lib_status_t, optiga_util_create, OPTIGA_INSTANCE_ID_0, OPTIGA_LIB_BUSY,
};

use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::digital::v2::OutputPin;

/// Provides high-level access to the Infineon Optiga Trust M hardware secure element.
pub struct OptigaM {
    lib_util: NonNull<optiga_util_t>,
}

#[allow(dead_code)]
#[repr(u16)]
enum OID {
    /// Global Life Cycle State
    GlobalLifeCycleStatus = 0xE0C0,
    /// Global Security Status
    GlobalSecurityStatus = 0xE0C1,
    /// Coprocessor UID
    CoprocessorUid = 0xE0C2,
    /// Global Life Cycle State
    SleepModeActivationDelay = 0xE0C3,
    /// Current limitation
    CurrentLimitation = 0xE0C4,
    /// Security Event Counter
    SecurityEventCounter = 0xE0C5,
    /// Device Public Key Certificate issued by IFX
    DevicePubkeyCertIFX = 0xE0E0,
    /// Project-Specific device Public Key Certificate
    DevicePubkeyCertPrjspc1 = 0xE0E1,
    /// Project-Specific device Public Key Certificate
    DevicePubkeyCertPrjspc2 = 0xE0E2,
    /// Project-Specific device Public Key Certificate
    DevicePubkeyCertPrjspc3 = 0xE0E3,
    /// First Device Private Key
    DevicePrikey1 = 0xE0F0,
    /// Second Device Private Key
    DevicePrikey2 = 0xE0F1,
    /// Third Device Private Key
    DevicePrikey3 = 0xE0F2,
    /// Fourth Device Private Key
    DevicePrikey4 = 0xE0F3,
    /// First RSA Device Private Key
    DevicePrikeyRSA1 = 0xE0FC,
    /// Second RSA Device Private Key
    DevicePrikeyRSA2 = 0xE0FD,
    /// Application Life Cycle Status
    ApplicationLifeCycleStatus = 0xF1C0,
    /// Application Security Status
    SecurityStatusA = 0xF1C1,
    /// Error codes
    ErrorCodes = 0xF1C2,
}

/// Create a crypt instance for use between operations.
fn crypt_create() -> NonNull<cbindings::optiga_crypt> {
    unsafe {
        NonNull::new(cbindings::optiga_crypt_create(
            cbindings::OPTIGA_INSTANCE_ID_0 as u8,
            Some(crate::optiga_util_callback),
            core::ptr::null_mut(),
        ))
        .expect("optiga_crypt_create() returned a null pointer")
    }
}

/// Destroy a crypt instance for use between operations.
fn crypt_destroy(lib_crypt: NonNull<cbindings::optiga_crypt>) {
    unsafe {
        let result: OptigaStatus = cbindings::optiga_crypt_destroy(lib_crypt.as_ptr()).into();
        match result {
            OptigaStatus::Success(_) => Ok(()),
            e => Err(e),
        }
        .unwrap();
    }
}

// TODO: write a metadata object based on python-optiga-trust's _parse_raw_meta
// https://infineon.github.io/python-optiga-trust/metadata.html

impl Drop for OptigaM {
    fn drop(&mut self) {
        call_optiga_func(|| unsafe {
            cbindings::optiga_util_close_application(self.lib_util.as_ptr(), 1)
        })
        .unwrap();

        let result = unsafe { cbindings::optiga_util_destroy(self.lib_util.as_ptr()) };

        match result.into() {
            OptigaStatus::Success(_) => Ok(()),
            e => Err(e),
        }
        .unwrap()
    }
}

impl OptigaM {
    /// Set an OID's metadata to a byteslice
    unsafe fn set_metadata(&mut self, oid: OID, data: &[u8]) -> Result<(), OptigaStatus> {
        let len: u8 = data
            .len()
            .try_into()
            .expect("metadata was too long, length must be able to fit into a u8");

        call_optiga_func(|| {
            cbindings::optiga_util_write_metadata(
                self.lib_util.as_ptr(),
                oid as u16,
                data.as_ptr(),
                len,
            )
        })?;

        assert!(usize::from(len) <= data.len());

        Ok(())
    }

    /// Read the metadata of an OID and write to the provided byteslice. returns the number of bytes in the provided byteslice used.
    unsafe fn get_metadata(&mut self, oid: OID, data: &mut [u8]) -> Result<usize, OptigaStatus> {
        let mut len: u16 = data.len() as u16;

        call_optiga_func(|| {
            cbindings::optiga_util_read_metadata(
                self.lib_util.as_ptr(),
                oid as u16,
                data.as_mut_ptr(),
                &mut len,
            )
        })?;

        assert!(usize::from(len) <= data.len());
        assert_ne!(len, 0);

        Ok(usize::from(len))
    }

    /// Set an OID to a byte slice..
    unsafe fn set_generic_data(
        &mut self,
        oid: OID,
        data: &[u8],
        offset: Option<u16>,
    ) -> Result<(), OptigaStatus> {
        let len: u16 = data.len().try_into().expect("metadata was too long");

        assert!(len < 1700);

        let offset = offset.unwrap_or(0);
        assert!(offset < 1700);

        call_optiga_func(|| {
            cbindings::optiga_util_write_data(
                self.lib_util.as_ptr(),
                oid as u16,
                cbindings::OPTIGA_UTIL_ERASE_AND_WRITE as u8,
                offset,
                data.as_ptr(),
                len,
            )
        })
    }

    /// Read the data of an OID and write to the provided byteslice. returns the number of bytes used.
    unsafe fn get_generic_data(
        &mut self,
        oid: OID,
        data: &mut [u8],
        offset: Option<u16>,
    ) -> Result<usize, OptigaStatus> {
        let mut len: u16 = data.len() as u16;
        assert!(data.len() < 1700);
        let offset = offset.unwrap_or(0);
        assert!(offset < 1700);

        call_optiga_func(|| {
            cbindings::optiga_util_read_data(
                self.lib_util.as_ptr(),
                oid as u16,
                offset,
                data.as_mut_ptr(),
                &mut len,
            )
        })?;

        assert!(usize::from(len) <= data.len());
        assert_ne!(len, 0);

        Ok(usize::from(len))
    }

    /// Get current limit for OPTIGA_TRUST_M in mA (6mA default, 15mA maximum)
    pub fn get_current_limit(&mut self) -> Result<u8, OptigaStatus> {
        let mut set_current: [u8; 1] = [0];
        unsafe {
            self.get_generic_data(OID::CurrentLimitation, &mut set_current, None)?;
        }

        Ok(set_current[0])
    }

    /// Set current limit for OPTIGA_TRUST_M in mA (6mA default, 15mA maximum)
    /// This is required for some operations.
    pub fn set_current_limit(&mut self, milliamps: u8) -> Result<(), OptigaStatus> {
        assert!((6..=15).contains(&milliamps));

        #[cfg(not(any(test, feature = "tester")))]
        defmt::info!("mA: {}", &milliamps);

        unsafe {
            self.set_generic_data(
                OID::CurrentLimitation,
                core::slice::from_ref(&milliamps),
                None,
            )?;
        }

        debug_assert!(self.get_current_limit()? == milliamps);

        Ok(())
    }

    /// Builds and returns a new instance of the SE. Only one device should be connected to the microcontroller at a time, and only one device can be used at a time.
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

        call_optiga_func(|| unsafe { optiga_util_open_application(lib_util.as_ptr(), 0) })
            .expect("was unable to initialize utility");

        OptigaM { lib_util }
    }

    /// Test that the i2c communication with the SE is functioning properly.
    pub fn test_optiga_communication(&mut self) -> Result<(), OptigaStatus> {
        use errors::OPTIGA_LIB_STATUS;

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
            while cbindings::PAL_I2C_EVENT_SUCCESS as u16 != OPTIGA_LIB_STATUS {
                OPTIGA_LIB_STATUS = cbindings::PAL_I2C_EVENT_BUSY.into();
                pal_return_status = cbindings::pal_i2c_write(
                    &optiga_pal_i2c_context_0,
                    transmit_buffer.as_mut_ptr(),
                    transmit_buffer.len() as u16,
                );

                if cbindings::PAL_STATUS_FAILURE as u16 == OPTIGA_LIB_STATUS {
                    break;
                }
            }
        }

        unsafe {
            while cbindings::PAL_I2C_EVENT_SUCCESS as u16 != OPTIGA_LIB_STATUS {
                OPTIGA_LIB_STATUS = cbindings::PAL_I2C_EVENT_BUSY.into();
                pal_return_status = cbindings::pal_i2c_read(
                    &optiga_pal_i2c_context_0,
                    recv_buffer.as_mut_ptr(),
                    recv_buffer.len() as u16,
                );

                if cbindings::PAL_STATUS_FAILURE as u16 == OPTIGA_LIB_STATUS {
                    break;
                }
            }
        }

        unsafe { handle_error(pal_return_status) }
    }

    // }


}

#[cfg(test)]
mod tests {
    use crate::OptigaSha256;

    #[test]
    fn dont_segfault() {
        use crate::OptigaM;
        use embedded_hal_mock::pin::State;
        use embedded_hal_mock::{i2c::Mock as I2CMock, pin::Mock as PinMock};
        use embedded_hal_mock::{
            i2c::Transaction as I2CTransaction, pin::Transaction as PinTransaction,
        };

        let rstpin = PinMock::new(&[
            PinTransaction::set(State::Low),
            PinTransaction::set(State::High),
        ]);
        let vccpin = PinMock::new(&[]);
        let i2cpin = I2CMock::new(&[
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
            I2CTransaction::read(48, vec![72, 128, 0, 5]),
            I2CTransaction::write(48, vec![128]),
            I2CTransaction::read(48, vec![129, 0, 0, 86, 48]),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![8, 128, 0, 0]),
            I2CTransaction::write(
                48,
                vec![
                    128, 3, 0, 21, 0, 240, 0, 0, 16, 210, 118, 0, 0, 4, 71, 101, 110, 65, 117, 116,
                    104, 65, 112, 112, 108, 201, 182,
                ],
            ),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![72, 128, 0, 5]),
            I2CTransaction::write(48, vec![128]),
            I2CTransaction::read(48, vec![129, 0, 0, 86, 48]),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![8, 128, 0, 0]),
            I2CTransaction::write(
                48,
                vec![
                    128, 3, 0, 21, 0, 240, 0, 0, 16, 210, 118, 0, 0, 4, 71, 101, 110, 65, 117, 116,
                    104, 65, 112, 112, 108, 201, 182,
                ],
            ),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![72, 128, 0, 5]),
            I2CTransaction::write(48, vec![128]),
            I2CTransaction::read(48, vec![129, 0, 0, 86, 48]),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![8, 128, 0, 0]),
            I2CTransaction::write(
                48,
                vec![
                    128, 3, 0, 21, 0, 240, 0, 0, 16, 210, 118, 0, 0, 4, 71, 101, 110, 65, 117, 116,
                    104, 65, 112, 112, 108, 201, 182,
                ],
            ),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![72, 128, 0, 5]),
            I2CTransaction::write(48, vec![128]),
            I2CTransaction::read(48, vec![129, 0, 0, 86, 48]),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![8, 128, 0, 0]),
            I2CTransaction::write(48, vec![128, 192, 0, 0, 10, 154]),
            I2CTransaction::write(
                48,
                vec![
                    128, 3, 0, 21, 0, 240, 0, 0, 16, 210, 118, 0, 0, 4, 71, 101, 110, 65, 117, 116,
                    104, 65, 112, 112, 108, 201, 182,
                ],
            ),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![72, 128, 0, 10]),
            I2CTransaction::write(48, vec![128]),
            I2CTransaction::read(48, vec![0, 0, 5, 0, 0, 0, 0, 0, 20, 135]),
            I2CTransaction::write(48, vec![128, 128, 0, 0, 12, 236]),
            I2CTransaction::write(
                48,
                vec![
                    128, 4, 0, 11, 0, 176, 226, 0, 6, 1, 0, 3, 97, 98, 99, 205, 31,
                ],
            ),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![200, 128, 0, 5]),
            I2CTransaction::write(48, vec![128]),
            I2CTransaction::read(48, vec![129, 0, 0, 86, 48]),
            I2CTransaction::write(48, vec![130]),
            I2CTransaction::read(48, vec![72, 128, 0, 45]),
            I2CTransaction::write(48, vec![128]),
            I2CTransaction::read(
                48,
                vec![
                    5, 0, 40, 0, 0, 0, 0, 35, 1, 0, 32, 186, 120, 22, 191, 143, 1, 207, 234, 65,
                    65, 64, 222, 93, 174, 34, 35, 176, 3, 97, 163, 150, 23, 122, 156, 180, 16, 255,
                    97, 242, 0, 21, 173, 113, 98,
                ],
            ),
            I2CTransaction::write(48, vec![128, 129, 0, 0, 86, 48]),
        ]);

        use sha2::{Digest, Sha256};

        let samplebits = ['a' as u8, 'b' as u8, 'c' as u8];

        let mut known_hash = Sha256::new();
        for bit in samplebits {
            Digest::update(&mut known_hash, &[bit]);
        }
        let known_good_hash_result = Digest::finalize(known_hash);

        let mut device = OptigaM::new(rstpin, vccpin, i2cpin);

        let mut optiga_hash_result = [0; 32];

        use super::DynDigest;

        let mut optiga_result = OptigaSha256::new(&mut device);
        optiga_result.update(&samplebits);
        optiga_result
            .finalize_into(&mut optiga_hash_result)
            .unwrap();

        assert_eq!(optiga_hash_result, known_good_hash_result[..]);
    }
}
