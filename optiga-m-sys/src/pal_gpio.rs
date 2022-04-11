use crate::{
    cbindings::{pal_gpio_t, pal_status_t, PAL_STATUS_SUCCESS},
    OPTIGA_TRUST_M_RESOURCES,
};

#[no_mangle]
pub unsafe extern "C" fn pal_gpio_deinit(_p_gpio_context: *const pal_gpio_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_gpio_init(_p_gpio_context: *const pal_gpio_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_gpio_set_high(p_gpio_context: *const pal_gpio_t) {
    match &mut OPTIGA_TRUST_M_RESOURCES {
        Some(periph) => {
            if p_gpio_context.is_null() {
                periph.set_pwr_high();
            } else {
                periph.set_rst_high();
            }
        }
        None => unreachable!(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pal_gpio_set_low(p_gpio_context: *const pal_gpio_t) {
    match &mut OPTIGA_TRUST_M_RESOURCES {
        Some(periph) => {
            if p_gpio_context.is_null() {
                periph.set_pwr_low();
            } else {
                periph.set_rst_low();
            }
        }
        None => unreachable!(),
    }
}
