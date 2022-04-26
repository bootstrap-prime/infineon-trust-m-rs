#[cfg(not(any(feature = "tester", test)))]
use systick::{delay::delay_ms, micros, millis};

#[cfg(feature = "tester")]
use std::time::Instant;

use crate::cbindings::{pal_status_t, PAL_STATUS_SUCCESS};

#[no_mangle]
pub unsafe extern "C" fn pal_os_timer_delay_in_milliseconds(milliseconds: u16) {
    #[cfg(not(any(test, feature = "tester")))]
    defmt::trace!("delayed");
    #[cfg(not(feature = "tester"))]
    delay_ms(milliseconds.into());
    #[cfg(feature = "tester")]
    std::thread::sleep(std::time::Duration::from_millis(milliseconds as u64));
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_timer_get_time_in_milliseconds() -> u32 {
    #[cfg(not(any(test, feature = "tester")))]
    defmt::trace!("got time");
    #[cfg(feature = "tester")]
    {
        crate::since_started.elapsed().as_millis() as u32
    }
    #[cfg(not(feature = "tester"))]
    {
        millis() as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_timer_get_time_in_microseconds() -> u32 {
    #[cfg(not(any(test, feature = "tester")))]
    defmt::trace!("got time");
    #[cfg(feature = "tester")]
    {
        crate::since_started.elapsed().as_micros() as u32
    }
    #[cfg(not(feature = "tester"))]
    {
        micros() as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn pal_timer_deinit() -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}

#[no_mangle]
pub unsafe extern "C" fn pal_timer_init() -> pal_status_t {
    PAL_STATUS_SUCCESS.into()
}
