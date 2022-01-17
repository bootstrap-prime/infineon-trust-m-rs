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

enum VDDorRST {
    PWR = 0,
    RST = 1,
}

// from https://github.com/Infineon/optiga-trust-m/wiki/Porting-Guide
// https://stackoverflow.com/questions/51524371/how-can-i-link-libraries-to-my-c-code-and-use-that-in-a-rust-binary
// https://github.com/Infineon/arduino-optiga-trust-m/blob/master/src/optiga_trustm/pal_os_event_arduino.cpp
// https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html

impl<RSTPin, VCCPin, I2CPin> OptigaTrustM<RSTPin, VCCPin, I2CPin>
where
    RSTPin: OutputPin,
    VCCPin: OutputPin,
    I2CPin: Write + Read,
{
    pub fn new(
        rst: RSTPin,
        pwr: VCCPin,
        i2c: I2CPin,
        timer: TIMER,
    ) -> OptigaTrustM<RSTPin, VCCPin, I2CPin> {
        OptigaTrustM {
            i2c,
            rst,
            pwr,
            timer,
        }
    }

    fn write_register(&mut self, reg: Register, byte: &[u8]) {}

    fn read_register(&mut self, reg: Register, byte: &mut [u8]) {}
}

enum I2CMode {
    Busy = 31,
    ResponseReady = 30,
    SoftReset = 27,
    ContinueRead = 26,
    RepeatedStart = 25,
    ClockStretching = 24,
    PresentLayer = 23,
}

enum Register {
    Data = 0x80,
    DataLen = 0x81,
    I2CState = 0x82,
    BaseAddr = 0x83,
    MaxSclFreq = 0x84,
    GuardTime = 0x85,
    TransTimeout = 0x86,
    PwrSaveTimeout = 0x87,
    SoftReset = 0x88,
    I2CMode = 0x89,
    // generated with
    // let range = 0x90..=0x9F;
    // let num: Vec<String> = (0x0_i32..=0xF_i32)
    //             .map(|e| format!("{:#X}", e).to_owned())
    //             .map(|e| e[2..].to_owned())
    //             .collect();

    // for (e, val) in num.iter().zip(range) {
    //     println!("    AppState{} = {:#X},", e, val);
    // }
    AppState0 = 0x90,
    AppState1 = 0x91,
    AppState2 = 0x92,
    AppState3 = 0x93,
    AppState4 = 0x94,
    AppState5 = 0x95,
    AppState6 = 0x96,
    AppState7 = 0x97,
    AppState8 = 0x98,
    AppState9 = 0x99,
    AppStateA = 0x9A,
    AppStateB = 0x9B,
    AppStateC = 0x9C,
    AppStateD = 0x9D,
    AppStateE = 0x9E,
    AppStateF = 0x9F,
    ForIFXUse1 = 0xA0,
    ForIFXUse2 = 0xA1,
}
