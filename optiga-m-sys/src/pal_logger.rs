use core::ptr::NonNull;

use crate::cbindings;
use cbindings::{pal_status_t, PAL_STATUS_FAILURE, PAL_STATUS_SUCCESS};
use cty::c_void;

#[no_mangle]
pub unsafe extern "C" fn pal_logger_init(_p_logger_context: *mut c_void) -> pal_status_t {
    // placeholder, this is accomplished by defmt
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_logger_deinit(_p_logger_context: *mut c_void) -> pal_status_t {
    // placeholder, this is accomplished by defmt
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_logger_read(
    _p_logger_context: *mut c_void,
    _p_log_data: *mut u8,
    _log_data_length: u32,
) -> pal_status_t {
    // placeholder, this is not necessary and is commented out in the arduino lib
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_logger_write(
    _p_logger_context: *mut c_void,
    p_log_data: *const u8,
    log_data_length: u32,
) -> pal_status_t {
    let p_log_data = NonNull::new(p_log_data as *mut _).unwrap().as_ptr();

    let data = core::slice::from_raw_parts(p_log_data, log_data_length as usize);
    if let Ok(data) = core::str::from_utf8(data) {
        #[cfg(not(any(test, feature = "tester")))]
        defmt::warn!("from tpm lib: {}", data);
        PAL_STATUS_SUCCESS.into()
    } else {
        PAL_STATUS_FAILURE.into()
    }
}
