use crate::{
    cbindings::{self, pal_i2c, pal_i2c_t, pal_status_t, PAL_STATUS_SUCCESS},
    OPTIGA_TRUST_M_RESOURCES,
};

#[cfg(not(any(test, feature = "tester")))]
use defmt::{dbg, trace};

// initializaiton/deinitialization and bitrate are handled by embedded_hal
#[no_mangle]
pub unsafe extern "C" fn pal_i2c_init(_p_i2c_context: *const pal_i2c_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_i2c_deinit(_p_i2c_context: *const pal_i2c_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_i2c_set_bitrate(
    _p_i2c_context: *const pal_i2c_t,
    _bitrate: u16,
) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_i2c_read(
    p_i2c_context: *const pal_i2c_t,
    p_data: *mut u8,
    length: u16,
) -> pal_status_t {
    #[cfg(not(any(test, feature = "tester")))]
    trace!("read i2c");
    let mut data = core::slice::from_raw_parts_mut(p_data, length.into());

    match (p_i2c_context.as_ref(), &mut OPTIGA_TRUST_M_RESOURCES) {
        (Some(ctx), Some(periph)) => {
            if periph.as_mut().read_i2c(ctx.slave_address, &mut data) {
                cbindings::PAL_I2C_EVENT_ERROR.into()
            } else {
                cbindings::PAL_I2C_EVENT_SUCCESS.into()
            }
        }
        (ctx, periph) => {
            #[cfg(not(any(test, feature = "tester")))]
            trace!(
                "ctx.is_some(): {}, periph.is_some(): {}",
                ctx.is_some(),
                periph.is_some()
            );
            cbindings::PAL_I2C_EVENT_ERROR.into()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pal_i2c_write(
    p_i2c_context: *const pal_i2c_t,
    p_data: *mut u8,
    length: u16,
) -> pal_status_t {
    #[cfg(not(any(test, feature = "tester")))]
    trace!("wrote i2c");
    let data = core::slice::from_raw_parts(p_data, length.into());

    match (p_i2c_context.as_ref(), &mut OPTIGA_TRUST_M_RESOURCES) {
        (Some(ctx), Some(periph)) => {
            if periph.as_mut().write_i2c(ctx.slave_address, data) {
                cbindings::PAL_I2C_EVENT_ERROR.into()
            } else {
                cbindings::PAL_I2C_EVENT_SUCCESS.into()
            }
        }
        (ctx, periph) => {
            #[cfg(not(any(test, feature = "tester")))]
            trace!(
                "ctx.is_some(): {}, periph.is_some(): {}",
                ctx.is_some(),
                periph.is_some()
            );
            cbindings::PAL_I2C_EVENT_ERROR.into()
        }
    }
}
