#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

/* set up allocator */
use alloc_cortex_m::CortexMHeap;
#[global_allocator]
pub static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

#[alloc_error_handler]
fn oom(_layout: core::alloc::Layout) -> ! {
    panic!("Out Of Memory");
    //panic!("{:?}", &layout);
}

fn setup_alloc_statics() {
    // Initialize allocator
    unsafe {
        ALLOCATOR.init(
            cortex_m_rt::heap_start() as usize,
            2048, // this is probably enough
        );
    }
}

/* set up logging and panic behavior */
use defmt_rtt as _;
use panic_probe as _;

#[defmt::panic_handler]
fn panic() -> ! {
    cortex_m::asm::udf()
}

/* set up device specific things */
// memory layout
use stm32f4xx_hal as _;

#[allow(dead_code)]
struct TestPeripherals {
    tpm_periphs: optiga_m::OptigaM,
}

#[defmt_test::tests]
#[cfg(test)]
mod tests {
    use defmt::{assert, assert_eq};
    use stm32f4xx_hal::{i2c::I2c, pac, prelude::*};

    #[init]
    fn init() -> super::TestPeripherals {
        super::setup_alloc_statics();

        let cp = cortex_m::Peripherals::take().unwrap();
        let dp = pac::Peripherals::take().unwrap();

        let rcc = dp.RCC.constrain();
        let clocks = rcc.cfgr.use_hse(25.mhz()).sysclk(48.mhz()).freeze();

        systick::init_with_frequency(cp.SYST, 25000000, 1000);
        systick::start();

        let gpioa = dp.GPIOA.split();
        let gpiob = dp.GPIOB.split();

        let tpm_periphs = {
            // these are left undefined, may be implemented in the future
            let rst = gpioa.pa0.into_push_pull_output().erase();
            let pwr = gpioa.pa1.into_push_pull_output().erase();

            let scl = gpiob
                .pb6
                .into_alternate()
                .internal_pull_up(true)
                .set_open_drain();
            let sda = gpiob
                .pb7
                .into_alternate()
                .internal_pull_up(true)
                .set_open_drain();

            (rst, pwr, I2c::new(dp.I2C1, (scl, sda), 100.khz(), &clocks))
        };

        let device = optiga_m::OptigaM::new(tpm_periphs.0, tpm_periphs.1, tpm_periphs.2);

        super::TestPeripherals {
            tpm_periphs: device,
        }
    }

    // ensure tpm is connected
    #[test]
    fn tpm_connected(p: &mut super::TestPeripherals) {
        let device = &mut p.tpm_periphs;

        device.test_optiga_communication().unwrap();
    }

    // Ensure functionality of tpm hash function
    #[test]
    fn tpm_hash(p: &mut super::TestPeripherals) {
        let device = &mut p.tpm_periphs;

        use sha2::{Digest, Sha256};

        let samplebits = ['a' as u8, 'b' as u8, 'c' as u8];

        let known_good_hash_result = Sha256::new().chain_update(&samplebits).finalize();

        use optiga_m::{DynDigest, OptigaSha256};
        let mut optiga_result = OptigaSha256::new(device);

        let mut optiga_hash_result = [0; 32];
        optiga_result.update(&samplebits);
        optiga_result
            .finalize_into(&mut optiga_hash_result)
            .unwrap();

        assert_eq!(optiga_hash_result, known_good_hash_result[..]);
    }

    // Test that random is outputting random bits
    #[test]
    fn tpm_random_generation(p: &mut super::TestPeripherals) {
        let device = &mut p.tpm_periphs;

        use rand_core::RngCore;
        // make sure it doesn't choke on sizes smaller than the minimum
        let mut random_buffer: [u8; 4] = [0; 4];
        device.fill_bytes(&mut random_buffer);

        defmt::trace!("{}", line!());

        // make sure it doesn't choke on sizes larger than the maximum
        let mut random_buffer: [u8; 300] = [0; 300];
        device.fill_bytes(&mut random_buffer);

        defmt::trace!("{}", line!());

        // make sure it's outputting actual randomness from the device instead of just repeating the same byte
        let mut random_buffer: [u8; 30] = [0; 30];
        device.fill_bytes(&mut random_buffer);

        defmt::trace!("{}", line!());

        assert_ne!(random_buffer, [0; 30]);

        assert!(random_buffer[2..]
            .iter()
            .enumerate()
            .any(|(index, member)| random_buffer
                [index.checked_sub(1).unwrap_or(random_buffer.len() - 1)]
                != *member));
    }

    // test key generation and signatures
    #[test]
    fn tpm_signature(_p: &mut super::TestPeripherals) {
        unimplemented!()
    }

    // test key generation and key exchange
    #[test]
    fn tpm_keyexchange(_p: &mut super::TestPeripherals) {
        unimplemented!()
    }

    // Ensure that the tpm is from a valid manufacturer
    #[test]
    fn tpm_authentic_mfr(_p: &mut super::TestPeripherals) {
        unimplemented!()
    }
}
