# infineon-trust-m-rs

Rust API over infineon's optiga-trust-m host stack.

## TODO
- Metadata creation and interpretation module
- Signature creation and interpretation, conforming to rust-crypto/signature traits
- Verification of chip authenticity
- Key exchange methods, conforming to rust-crypto/KEM traits 
- Allow operation when compiled in release mode 
(when compiled in release mode, it will either cause strange errors and load-bearing unwrap()s, segfault, or loop infinitely)
- audit for memory unsafety and unsoundness 
- Chip hibernation
- Mock library implementation for testing elsewhere
- decompose method for SE to turn struct back into components

Stretch goals (not necessary, likely not implemented in the interests of time):
- AES encryption handling, conforming to rust-crypto/cipher
- better handling of logs (defmt log backend?)
- certificate handling

## Required hardware for testing
- STM32F411 black pill (available on [adafruit](https://www.adafruit.com/product/4877))
- Optiga-trust-M (also available on [adafruit](https://www.adafruit.com/product/4351))
- Jumper wires
- breadboard
- STLink v2 debugger

Configured as such:
(mcu) (trustm)
A0 -> RST
B7 -> SDA
B6 -> SCL
GND -> GND
3V3 -> VCC

## How to test
- make your changes
- cd to testsuite
- run "cargo run"
