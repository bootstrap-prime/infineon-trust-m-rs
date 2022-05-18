use crate::{
    cbindings::{pal_gpio_t, pal_status_t, PAL_STATUS_SUCCESS},
    OPTIGA_TRUST_M_RESOURCES,
};
use core::ptr::NonNull;

#[no_mangle]
pub extern "C" fn pal_gpio_deinit(_p_gpio_context: *const pal_gpio_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub extern "C" fn pal_gpio_init(_p_gpio_context: *const pal_gpio_t) -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub extern "C" fn pal_gpio_set_high(_p_gpio_context: *const pal_gpio_t) {
    let potential_pin = unsafe {
        NonNull::new(_p_gpio_context as *mut pal_gpio_t)
            .map(|ctx| ctx.as_ref().p_gpio_hw)
            .map(NonNull::new)
            .flatten()
    };

    if let Some(pin) = potential_pin {
        let pin = pin.as_ptr() as u8;

        assert!(pin == 2 || pin == 1);

        let periph = unsafe { OPTIGA_TRUST_M_RESOURCES.as_mut() }
            .expect("OPTIGA_TRUST_M_RESOURCES was not initialized.");

        match pin {
            1 => periph.as_mut().set_pwr_high(),
            2 => periph.as_mut().set_rst_high(),
            e => panic!(
                "value {} was not a configured value, memory mangling has failed!",
                e
            ),
        };
    }
}

#[no_mangle]
pub extern "C" fn pal_gpio_set_low(_p_gpio_context: *const pal_gpio_t) {
    let potential_pin = unsafe {
        NonNull::new(_p_gpio_context as *mut pal_gpio_t)
            .map(|ctx| ctx.as_ref().p_gpio_hw)
            .map(NonNull::new)
            .flatten()
    };

    if let Some(pin) = potential_pin {
        let pin = pin.as_ptr() as u8;

        assert!(pin == 2 || pin == 1);

        let periph = unsafe { OPTIGA_TRUST_M_RESOURCES.as_mut() }
            .expect("OPTIGA_TRUST_M_RESOURCES was not initialized.");

        match pin {
            1 => periph.as_mut().set_pwr_low(),
            2 => periph.as_mut().set_rst_low(),
            e => panic!(
                "value {} was not a configured value, memory mangling has failed!",
                e
            ),
        };
    }
}
