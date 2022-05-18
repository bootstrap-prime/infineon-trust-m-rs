use crate::call_optiga_func;
use crate::cbindings;
use crate::OptigaM;
use crate::OptigaStatus;

/// Get random slice of bytes from the device's TRNG.
/// The device's TRNG generates random numbers in blocks of 8 to 256 bytes - if an input buffer exceeds this, the hardware is called multiple times to fill it.
/// If an input buffer is less than the minimum length (8 bytes), the hardware will call the minimum length and discard unused bytes.
/// This device is not in the CPU- ideally, this should be used directly only by those that absolutely need a CSTRNG, or to seed a PRNG.
/// Due to constraints on std::error (specifically, there being no core::error), rand_core makes you output numerical error codes. A convenience implementation of From<rand_core::Error> for OptigaStatus has been provided.
impl rand_core::RngCore for OptigaM {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        // there is a valid range of bytes you can request, 8 to 256. any higher or lower, the device will get mad at you.
        // rust doesn't provide a mechanism to limit the size of a byte, and I don't want to add a new error code, so it should handle arbitrary slice sizes

        // FnMut(&mut [u8]) -> Result<(), OptigaStatus>, interface to internal cbindings optiga call
        let random_internal = |buf_chunk: &mut [u8]| {
            call_optiga_func(|| unsafe {
                cbindings::optiga_crypt_random(
                    self.lib_crypt.as_ptr(),
                    cbindings::optiga_rng_type_OPTIGA_RNG_TYPE_TRNG,
                    buf_chunk.as_mut_ptr(),
                    buf_chunk.len().try_into().unwrap(),
                )
            })
        };

        // chunk the slice into the maximum length for the slice per call to the device.
        for chunk in bytes.chunks_mut(256) {
            if chunk.len() < 8 {
                // if the size is less than the minimum allowed length, request the minimum length and discard unused bytes.
                let mut buf: [u8; 8] = [0; 8];

                random_internal(&mut buf)?;
                chunk.copy_from_slice(&buf[..chunk.len()]);
            } else {
                random_internal(chunk)?;
            }
        }

        Ok(())
    }
}

impl rand_core::CryptoRng for OptigaM {}

impl From<OptigaStatus> for rand_core::Error {
    fn from(error: OptigaStatus) -> rand_core::Error {
        TryInto::<core::num::NonZeroU32>::try_into(Into::<u16>::into(error) as u32)
            .unwrap()
            .into()
    }
}

impl From<rand_core::Error> for OptigaStatus {
    fn from(error: rand_core::Error) -> OptigaStatus {
        let error: u16 = error.code().and_then(|e| e.get().try_into().ok()).unwrap();

        error.into()
    }
}
