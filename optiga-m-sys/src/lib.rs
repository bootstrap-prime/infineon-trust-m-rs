#![no_std]
// Safety: users must not define more than one module at a time.

// ignore all the errors in the generated rust bindings, otherwise this gets really annoying
pub mod cbindings {
    #![allow(dead_code)]
    #![allow(non_camel_case_types)]
    #![allow(broken_intra_doc_links)]
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::digital::v2::OutputPin;

use systick::{delay::delay_ms, micros, millis};

pub struct OptigaTrustM<RSTPin, VCCPin, I2CPin>
where
    RSTPin: OutputPin,
    VCCPin: OutputPin,
    I2CPin: Write + Read,
{
    i2c: I2CPin,
    rst: RSTPin,
    pwr: VCCPin,
}

trait OptigaResources {
    fn set_rst_high(&mut self) -> bool;
    fn set_rst_low(&mut self) -> bool;

    fn set_pwr_high(&mut self) -> bool;
    fn set_pwr_low(&mut self) -> bool;

    fn read_i2c(&mut self, addr: u8, data: &mut [u8]) -> bool;
    fn write_i2c(&mut self, addr: u8, data: &[u8]) -> bool;
}

#[allow(dead_code)]
enum VDDorRST {
    PWR = 0,
    RST = 1,
}

impl<RSTPin, VCCPin, I2CPin> OptigaResources for OptigaTrustM<RSTPin, VCCPin, I2CPin>
where
    RSTPin: OutputPin,
    VCCPin: OutputPin,
    I2CPin: Write + Read,
{
    fn set_rst_high(&mut self) -> bool {
        self.rst.set_high().is_ok()
    }
    fn set_rst_low(&mut self) -> bool {
        self.rst.set_low().is_ok()
    }

    fn set_pwr_high(&mut self) -> bool {
        self.pwr.set_high().is_ok()
    }
    fn set_pwr_low(&mut self) -> bool {
        self.pwr.set_low().is_ok()
    }

    fn read_i2c(&mut self, addr: u8, data: &mut [u8]) -> bool {
        self.i2c.read(addr, data).is_ok()
    }
    fn write_i2c(&mut self, addr: u8, data: &[u8]) -> bool {
        self.i2c.write(addr, data).is_ok()
    }
}

// from https://github.com/Infineon/optiga-trust-m/wiki/Porting-Guide
// https://stackoverflow.com/questions/51524371/how-can-i-link-libraries-to-my-c-code-and-use-that-in-a-rust-binary
// https://github.com/Infineon/arduino-optiga-trust-m/blob/master/src/optiga_trustm/pal_os_event_arduino.cpp
// https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html

unsafe impl<RSTPin, VCCPin, I2CPin> Send for OptigaTrustM<RSTPin, VCCPin, I2CPin>
where
    RSTPin: OutputPin,
    VCCPin: OutputPin,
    I2CPin: Write + Read,
{
}

// this global mutex badness is temporary, until we get capabilities
// and lets callbacks get called without having to figure out how to inject
// context. this isn't ideal.
extern crate alloc;
use alloc::boxed::Box;
static mut OPTIGA_TRUST_M_RESOURCES: Option<Box<dyn OptigaResources + Send>> = None;

#[allow(no_mangle_generic_items)]
impl<RSTPin: 'static, VCCPin: 'static, I2CPin: 'static> OptigaTrustM<RSTPin, VCCPin, I2CPin>
where
    RSTPin: OutputPin,
    VCCPin: OutputPin,
    I2CPin: Write + Read,
{
    pub unsafe fn setup_new(rst: RSTPin, pwr: VCCPin, i2c: I2CPin) {
        // user will need to configure the systick timer
        match &OPTIGA_TRUST_M_RESOURCES {
            Some(_) => panic!("Optiga Trust M already defined! Cannot use two modules at the same time due to FFI nonsense."),
            None => OPTIGA_TRUST_M_RESOURCES = Some(Box::new(OptigaTrustM { i2c, rst, pwr })),
        }
    }

    // pub unsafe fn decompose() -> (RSTPin, VCCPin, I2CPin) {
    //     use core::any::Any;
    //     match OPTIGA_TRUST_M_RESOURCES {
    //         Some(a) => a.downcast_ref::<OptigaTrustM>(),
    //         None => panic!("Attempting to decompose Optiga before it has been initialized!"),
    //     }
    // }
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_gpio_set_high(which_pin: u8) -> bool {
    match &mut OPTIGA_TRUST_M_RESOURCES {
        Some(periph) => match which_pin {
            0 => periph.set_pwr_high(),
            1 => periph.set_rst_high(),
            _ => unreachable!(),
        },
        None => unreachable!(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_gpio_set_low(which_pin: u8) -> bool {
    match &mut OPTIGA_TRUST_M_RESOURCES {
        Some(periph) => match which_pin {
            0 => periph.set_pwr_low(),
            1 => periph.set_rst_low(),
            _ => unreachable!(),
        },
        None => unreachable!(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_i2c_read(slave_address: u8, data: *mut u8, len: u16) -> bool {
    defmt::info!("read i2c");
    let mut data = core::slice::from_raw_parts_mut(data, len.into());

    match &mut OPTIGA_TRUST_M_RESOURCES {
        Some(periph) => periph.read_i2c(slave_address, &mut data),
        None => unreachable!(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_i2c_write(slave_address: u8, data: *const u8, len: u16) -> bool {
    defmt::info!("wrote i2c");
    let data = core::slice::from_raw_parts(data, len.into());

    match &mut OPTIGA_TRUST_M_RESOURCES {
        Some(periph) => periph.write_i2c(slave_address, data),
        None => unreachable!(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_logger_log(log_data: *const u8, length: u32) {
    let data = core::slice::from_raw_parts(log_data, length as usize);
    let data = core::str::from_utf8(data).unwrap();
    defmt::warn!("{}", data);
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_timer_delay_ms(milliseconds: u16) {
    defmt::info!("delayed");
    delay_ms(milliseconds.into());
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_timer_get_time_ms() -> u32 {
    defmt::info!("got time");
    millis() as u32
}

#[no_mangle]
pub unsafe extern "C" fn rust_hal_timer_get_time_us() -> u32 {
    defmt::info!("got time");
    micros() as u32
}

use naive_timer::Timer;

// Can't be a none value because sometimes a null callback is passed through, but a reference
// to a valid event is always required.
static mut pal_os_event_0: Option<cbindings::pal_os_event_t> = Some(cbindings::pal_os_event {
    is_event_triggered: false as u8,
    callback_registered: None,
    callback_ctx: core::ptr::null_mut(),
    os_timer: core::ptr::null_mut(),
});
static mut pal_os_event_cback_timer: Option<Timer> = None;

// handle the callback stack
#[no_mangle]
pub unsafe extern "C" fn pal_os_event_destroy(event: *mut cbindings::pal_os_event_t) {
    pal_os_event_0 = None;
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_event_create(
    callback: cbindings::register_callback,
    callback_args: *mut cty::c_void,
) -> *mut cbindings::pal_os_event_t {
    if !callback.is_some() && !callback_args.is_null() {
        pal_os_event_start(
            &mut pal_os_event_0.unwrap() as *mut cbindings::pal_os_event_t,
            callback,
            callback_args,
        );
    }

    return &mut pal_os_event_0.unwrap() as *mut cbindings::pal_os_event_t;
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_event_trigger_registered_callback() {
    if let Some(event) = pal_os_event_0 {
        if event.is_event_triggered != 0 {
            let mut event = pal_os_event_0.take().unwrap();
            event.is_event_triggered = true as u8;
            let callback = event.callback_registered.take().unwrap();
            callback(event.callback_ctx);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_event_register_callback_oneshot(
    p_pal_os_event: *mut cbindings::pal_os_event_t,
    callback: cbindings::register_callback,
    callback_args: *mut cty::c_void,
    time_us: u32,
) {
    let os_event: &mut cbindings::pal_os_event_t = p_pal_os_event.as_mut().unwrap();

    *os_event = cbindings::pal_os_event {
        is_event_triggered: false as u8,
        callback_registered: callback,
        callback_ctx: callback_args,
        os_timer: core::ptr::null_mut(),
    };

    struct CallbackCtx(*mut cty::c_void);
    unsafe impl Send for CallbackCtx {}
    unsafe impl Sync for CallbackCtx {}
    impl CallbackCtx {
        unsafe fn callfunc(self, callback: cbindings::register_callback) {
            if let Some(callback) = callback {
                let CallbackCtx(context) = self;
                callback(context);
            }
        }
    }

    let context = CallbackCtx(os_event.callback_ctx);

    let timer: &mut _ = pal_os_event_cback_timer.get_or_insert(Timer::default());

    timer.add(
        core::time::Duration::from_micros(time_us as u64 + systick::micros()),
        |_| {
            context.callfunc(os_event.callback_registered);
        },
    );
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_event_start(
    p_pal_os_event: *mut cbindings::pal_os_event_t,
    callback: cbindings::register_callback,
    callback_args: *mut cty::c_void,
) {
    let mut os_event: &mut cbindings::pal_os_event_t = p_pal_os_event.as_mut().unwrap();

    if os_event.is_event_triggered == false as u8 {
        os_event.is_event_triggered = true as u8;
        pal_os_event_register_callback_oneshot(p_pal_os_event, callback, callback_args, 1000);
    }
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_event_stop(p_pal_os_event: *mut cbindings::pal_os_event_t) {
    let mut os_event: &mut cbindings::pal_os_event_t = p_pal_os_event.as_mut().unwrap();
    os_event.is_event_triggered = false as u8;
}

#[no_mangle]
pub unsafe extern "C" fn pal_os_event_process() {
    let timer: &mut _ = pal_os_event_cback_timer.get_or_insert(Timer::default());

    timer.expire(core::time::Duration::from_micros(systick::micros()));
}

mod calloc;
