use crate::{
    cbindings::{pal_gpio_t, pal_status_t, PAL_STATUS_SUCCESS},
    OPTIGA_TRUST_M_RESOURCES,
};

#[no_mangle]
pub extern "C" fn pal_gpio_deinit(_p_gpio_context: *const pal_gpio_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub extern "C" fn pal_gpio_init(_p_gpio_context: *const pal_gpio_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub extern "C" fn pal_gpio_set_high(_p_gpio_context: *const pal_gpio_t) {}

#[no_mangle]
pub extern "C" fn pal_gpio_set_low(_p_gpio_context: *const pal_gpio_t) {}
