use core::ptr::NonNull;

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
    let p_data = NonNull::new(p_data).unwrap().as_ptr();
    let mut data = core::slice::from_raw_parts_mut(p_data, length.into());

    let ctx: &pal_i2c = NonNull::new(p_i2c_context as *mut _)
        .expect("i2c context in read was a null pointer")
        .as_ref();
    let periph = OPTIGA_TRUST_M_RESOURCES
        .as_mut()
        .expect("OPTIGA_TRUST_M_RESOURCES was not initialized.");

    let (fn_result, handler_result) = if periph.as_mut().read_i2c(ctx.slave_address, &mut data) {
        (
            cbindings::PAL_STATUS_SUCCESS.into(),
            cbindings::PAL_I2C_EVENT_SUCCESS.into(),
        )
    } else {
        (
            cbindings::PAL_STATUS_FAILURE.into(),
            cbindings::PAL_I2C_EVENT_ERROR.into(),
        )
    };

    // #[cfg(not(any(test, feature = "tester")))]
    // trace!("read i2c bytes {=[u8]}", data);

    if let Some(handler) = NonNull::new(ctx.upper_layer_event_handler).map(NonNull::as_ptr) {
        if let Some(context) = NonNull::new(ctx.p_upper_layer_ctx).map(NonNull::as_ptr) {
            let handler: cbindings::upper_layer_callback_t = Some(core::mem::transmute(handler));
            let handler = handler.unwrap();
            handler(context, handler_result);
        } else {
            #[cfg(not(any(test, feature = "tester")))]
            trace!("context was null");
        }
    } else {
        #[cfg(not(any(test, feature = "tester")))]
        trace!("handler was null");
    }

    fn_result
}

#[no_mangle]
pub unsafe extern "C" fn pal_i2c_write(
    p_i2c_context: *const pal_i2c_t,
    p_data: *mut u8,
    length: u16,
) -> pal_status_t {
    #[cfg(not(any(test, feature = "tester")))]
    trace!("wrote i2c");

    let ctx: &pal_i2c = NonNull::new(p_i2c_context as *mut _)
        .expect("i2c context in write was a null pointer")
        .as_ref();
    let periph = OPTIGA_TRUST_M_RESOURCES
        .as_mut()
        .expect("OPTIGA_TRUST_M_RESOURCES was not initialized.");

    let p_data = NonNull::new(p_data).unwrap().as_ptr();
    let data = core::slice::from_raw_parts(p_data, length.into());

    // #[cfg(not(any(test, feature = "tester")))]
    // trace!("writing i2c byte {=[u8]}", data);

    let (fn_result, handler_result) = if periph.as_mut().write_i2c(ctx.slave_address, data) {
        (
            cbindings::PAL_STATUS_SUCCESS.into(),
            cbindings::PAL_I2C_EVENT_SUCCESS.into(),
        )
    } else {
        (
            cbindings::PAL_STATUS_FAILURE.into(),
            cbindings::PAL_I2C_EVENT_ERROR.into(),
        )
    };

    if let Some(handler) = NonNull::new(ctx.upper_layer_event_handler).map(NonNull::as_ptr) {
        if let Some(context) = NonNull::new(ctx.p_upper_layer_ctx).map(NonNull::as_ptr) {
            let handler: cbindings::upper_layer_callback_t = Some(core::mem::transmute(handler));
            let handler = handler.unwrap();
            handler(context, handler_result);
        } else {
            #[cfg(not(any(test, feature = "tester")))]
            trace!("context was null");
        }
    } else {
        #[cfg(not(any(test, feature = "tester")))]
        trace!("handler was null");
    }

    fn_result
}
