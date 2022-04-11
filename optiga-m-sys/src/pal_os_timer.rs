use systick::{delay::delay_ms, micros, millis};

use crate::cbindings::{pal_status_t, PAL_STATUS_SUCCESS};

#[no_mangle]
pub unsafe extern "C" fn pal_os_timer_delay_in_milliseconds(milliseconds: u16) {
    defmt::trace!("delayed");
    delay_ms(milliseconds.into());
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_timer_get_time_in_milliseconds() -> u32 {
    defmt::trace!("got time");
    millis() as u32
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_timer_get_time_in_microseconds() -> u32 {
    defmt::trace!("got time");
    micros() as u32
}

#[no_mangle]
pub unsafe extern "C" fn pal_timer_deinit() -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_timer_init() -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}
