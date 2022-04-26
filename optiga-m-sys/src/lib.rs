#![cfg_attr(not(any(test, feature = "tester")), no_std)]
#![feature(option_get_or_insert_default)]
// Safety: users must not define more than one module at a time.

#[cfg(feature = "tester")]
lazy_static::lazy_static! {
    pub static ref since_started: std::time::Instant = std::time::Instant::now();
}

// ignore all the errors in the generated rust bindings, otherwise this gets really annoying
pub mod cbindings {
    #![allow(dead_code)]
    #![allow(non_camel_case_types)]
    #![allow(broken_intra_doc_links)]
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use core::fmt::Debug;

use cbindings::{pal_status_t, PAL_STATUS_SUCCESS};
use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::digital::v2::OutputPin;

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

pub mod calloc;
pub mod pal_gpio;
pub mod pal_i2c;
pub mod pal_logger;
pub mod pal_os_event;
pub mod pal_os_timer;
