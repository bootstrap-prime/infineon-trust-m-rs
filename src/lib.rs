use embedded_hal::blocking::i2c::{Read, Write};
use embedded_hal::digital::v2::OutputPin;
use embedded_hal::timer::CountDown;

pub struct OptigaTrustM<RSTPin, VCCPin, I2CPin, TIMER>
where
    RSTPin: OutputPin,
    VCCPin: OutputPin,
    I2CPin: Write + Read,
    TIMER: CountDown,
{
    i2c: I2CPin,
    rst: RSTPin,
    pwr: VCCPin,
    timer: TIMER,
}

enum VDDorRST {
    PWR = 0,
    RST = 1,
}

// from https://github.com/Infineon/optiga-trust-m/wiki/Porting-Guide
// https://stackoverflow.com/questions/51524371/how-can-i-link-libraries-to-my-c-code-and-use-that-in-a-rust-binary
// https://github.com/Infineon/arduino-optiga-trust-m/blob/master/src/optiga_trustm/pal_os_event_arduino.cpp
// https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html

#[allow(no_mangle_generic_items)]
impl<RSTPin, VCCPin, I2CPin, TIMER> OptigaTrustM<RSTPin, VCCPin, I2CPin, TIMER>
where
    RSTPin: OutputPin,
    VCCPin: OutputPin,
    I2CPin: Write + Read,
    TIMER: CountDown,
{
    pub fn new(
        rst: RSTPin,
        pwr: VCCPin,
        i2c: I2CPin,
        timer: TIMER,
    ) -> OptigaTrustM<RSTPin, VCCPin, I2CPin, TIMER> {
        OptigaTrustM {
            i2c,
            rst,
            pwr,
            timer,
        }
    }

    #[no_mangle]
    pub extern "C" fn rust_hal_gpio_set_high(&mut self, context: pal_gpio_t) -> bool {
        match context.p_gpio_hw as u8 {
            0 => self.pwr.set_high().is_ok(),
            1 => self.rst.set_high().is_ok(),
            _ => unreachable!(),
        }
    }

    #[no_mangle]
    pub extern "C" fn rust_hal_gpio_set_low(&mut self, context: pal_gpio_t) -> bool {
        match context.p_gpio_hw as u8 {
            0 => self.pwr.set_low().is_ok(),
            1 => self.rst.set_low().is_ok(),
            _ => unreachable!(),
        }
    }

    #[no_mangle]
    pub extern "C" fn rust_hal_i2c_read(
        &mut self,
        context: *const pal_i2c_t,
        data: *mut u8,
        len: u16,
    ) -> bool {
        let mut data = unsafe { core::slice::from_raw_parts(data, len.into()) };
        let addr = context.slave_address as u8;

        self.i2c.read(addr, &mut data).is_ok()
    }

    #[no_mangle]
    pub extern "C" fn rust_hal_i2c_write(
        &mut self,
        context: *const pal_i2c_t,
        data: *mut u8,
        len: u16,
    ) -> bool {
        let mut data = unsafe { core::slice::from_raw_parts(data, len.into()) };
        let addr = context.slave_address as u8;

        self.i2c.write(addr, &mut data).is_ok()
    }
}
