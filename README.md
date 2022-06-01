# infineon-trust-m-rs

Rust API over infineon's optiga-trust-m host stack.

## TODO
- Metadata creation and interpretation module
- Signature creation and interpretation, conforming to rust-crypto/signature traits
- Certificate handling
- Verification of authenticity, using certificate handling
- Key exchange methods, conforming to rust-crypto/KEM traits 
- Allow operation when compiled in release mode 
(when compiled in release mode, it will either cause strange errors and load-bearing unwrap()s, segfault, or loop infinitely)
- audit for memory unsafety and unsoundness 
- Chip hibernation

Optional, not necessary, and will likely not be implemented in the interests of time:
- AES encryption handling, conforming to rust-crypto/cipher

## Required hardware for testing
- STM32F411 black pill (available on [adafruit](https://www.adafruit.com/product/4877))
- Optiga-trust-M (also available on [adafruit](https://www.adafruit.com/product/4351))
- Jumper wires
- breadboard
- STLink v2 debugger
