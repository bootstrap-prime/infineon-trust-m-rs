use crate::cbindings;
use core::ptr::NonNull;
use cty::c_void;
use naive_timer::Timer;

// Can't be a none value because sometimes a null callback is passed through, but a reference
// to a valid event is always required.
const DEFAULT_EVENT: cbindings::pal_os_event = cbindings::pal_os_event {
    is_event_triggered: false as u8,
    callback_registered: None,
    callback_ctx: core::ptr::null_mut(),
    os_timer: core::ptr::null_mut(),
    sync_flag: 0,
    timeout_us: 0,
};

static mut PAL_OS_EVENT_0: Option<cbindings::pal_os_event_t> = Some(DEFAULT_EVENT);
static mut PAL_OS_EVENT_CBACK_TIMER: Option<Timer> = None;

// handle the callback stack
#[no_mangle]
pub extern "C" fn pal_os_event_destroy(_event: *mut cbindings::pal_os_event_t) {
    unsafe {
        PAL_OS_EVENT_0 = None;
    }
}

#[no_mangle]
pub extern "C" fn pal_os_event_create(
    callback: cbindings::register_callback,
    callback_args: *mut cty::c_void,
) -> *mut cbindings::pal_os_event_t {
    let event = unsafe { &mut PAL_OS_EVENT_0.unwrap() as *mut cbindings::pal_os_event_t };

    if !callback.is_none() && !callback_args.is_null() {
        pal_os_event_start(event, callback, callback_args);
    }

    return event;
}

#[no_mangle]
pub extern "C" fn pal_os_event_trigger_registered_callback() {
    if let Some(ref mut event) = unsafe { PAL_OS_EVENT_0 } {
        if let Some(callback) = event.callback_registered {
            unsafe {
                callback(event.callback_ctx);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn pal_os_event_register_callback_oneshot(
    p_pal_os_event: *mut cbindings::pal_os_event_t,
    callback: cbindings::register_callback,
    callback_args: *mut cty::c_void,
    time_us: u32,
) {
    assert!(!p_pal_os_event.is_null());

    let os_event: &mut cbindings::pal_os_event_t = unsafe { p_pal_os_event.as_mut().unwrap() };

    os_event.callback_registered = callback;
    os_event.callback_ctx = callback_args;

    struct CallbackCtx(NonNull<cty::c_void>);
    unsafe impl Send for CallbackCtx {}
    unsafe impl Sync for CallbackCtx {}
    impl CallbackCtx {
        unsafe fn callfunc(self, callback: cbindings::register_callback) {
            if let Some(callback) = callback {
                assert!(!(callback as *mut c_void).is_null());

                let CallbackCtx(context) = self;
                callback(context.as_ptr());
            }
        }
    }

    let context =
        CallbackCtx(NonNull::new(os_event.callback_ctx).expect("callback context was null"));

    let timer: &mut _ = unsafe { PAL_OS_EVENT_CBACK_TIMER.get_or_insert(Timer::default()) };

    #[cfg(not(any(feature = "tester", test)))]
    let current_time = core::time::Duration::from_micros(systick::micros());
    #[cfg(any(feature = "tester", test))]
    let current_time = crate::SINCE_STARTED.elapsed();

    let deadline = current_time + core::time::Duration::from_micros(time_us as u64);

    assert!(deadline > current_time);

    timer.add(deadline, move |_| {
        assert!(callback.is_some());
        unsafe {
            context.callfunc(callback);
        }
    });
}

#[no_mangle]
pub extern "C" fn pal_os_event_start(
    p_pal_os_event: *mut cbindings::pal_os_event_t,
    callback: cbindings::register_callback,
    callback_args: *mut cty::c_void,
) {
    if let Some(ref mut os_event) = unsafe { p_pal_os_event.as_mut() } {
        if os_event.is_event_triggered == false as u8 {
            os_event.is_event_triggered = true as u8;
            pal_os_event_register_callback_oneshot(p_pal_os_event, callback, callback_args, 1000);
        }
    }
}

#[no_mangle]
pub extern "C" fn pal_os_event_stop(p_pal_os_event: *mut cbindings::pal_os_event_t) {
    if let Some(ref mut os_event) = unsafe { p_pal_os_event.as_mut() } {
        os_event.is_event_triggered = false as u8;
    }
}

#[no_mangle]
pub extern "C" fn pal_os_event_process() {
    let timer: &mut _ = unsafe { PAL_OS_EVENT_CBACK_TIMER.get_or_insert(Timer::default()) };

    timer.expire({
        #[cfg(not(feature = "tester"))]
        {
            core::time::Duration::from_micros(systick::micros())
        }

        #[cfg(feature = "tester")]
        {
            crate::SINCE_STARTED.elapsed()
        }
    });
}
