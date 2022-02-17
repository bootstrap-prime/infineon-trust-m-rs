#![no_std]
// Safety: users must not define more than one module at a time.

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
    pub fn setup_new(rst: RSTPin, pwr: VCCPin, i2c: I2CPin) {
        // user will need to configure the systick timer
        let cursed_global_precursor = OptigaTrustM { i2c, rst, pwr };
        unsafe {
            match &OPTIGA_TRUST_M_RESOURCES {
                Some(_) => panic!("Optiga Trust M already defined! Cannot use two modules at the same time due to FFI nonsense."),
                None => OPTIGA_TRUST_M_RESOURCES = Some(Box::new(cursed_global_precursor)),
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_hal_gpio_set_high(which_pin: u8) -> bool {
    unsafe {
        match &mut OPTIGA_TRUST_M_RESOURCES {
            Some(periph) => match which_pin {
                0 => periph.set_pwr_high(),
                1 => periph.set_rst_high(),
                _ => unreachable!(),
            },
            None => unreachable!(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_hal_gpio_set_low(which_pin: u8) -> bool {
    unsafe {
        match &mut OPTIGA_TRUST_M_RESOURCES {
            Some(periph) => match which_pin {
                0 => periph.set_pwr_low(),
                1 => periph.set_rst_low(),
                _ => unreachable!(),
            },
            None => unreachable!(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_hal_i2c_read(slave_address: u8, data: *mut u8, len: u16) -> bool {
    let mut data = unsafe { core::slice::from_raw_parts_mut(data, len.into()) };

    unsafe {
        match &mut OPTIGA_TRUST_M_RESOURCES {
            Some(periph) => periph.read_i2c(slave_address, &mut data),
            None => unreachable!(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_hal_i2c_write(slave_address: u8, data: *const u8, len: u16) -> bool {
    let data = unsafe { core::slice::from_raw_parts(data, len.into()) };

    unsafe {
        match &mut OPTIGA_TRUST_M_RESOURCES {
            Some(periph) => periph.write_i2c(slave_address, data),
            None => unreachable!(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_hal_logger_log(log_data: *const u8, length: u32) {
    let data = unsafe { core::slice::from_raw_parts(log_data, length as usize) };
    let data = core::str::from_utf8(data).unwrap();
    defmt::warn!("{}", data);
}

#[no_mangle]
pub extern "C" fn rust_hal_timer_delay_ms(milliseconds: u16) {
    delay_ms(milliseconds.into());
}

#[no_mangle]
pub extern "C" fn rust_hal_timer_get_time_ms() -> u32 {
    millis() as u32
}

#[no_mangle]
pub extern "C" fn rust_hal_timer_get_time_us() -> u32 {
    micros() as u32
}
