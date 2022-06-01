#![no_std]
#![cfg_attr(test, no_main)]

use defmt_rtt as _;
use panic_probe as _;
use stm32f4xx_hal as _;

#[defmt_test::tests]
mod tests {}
