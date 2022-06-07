use crate::cbindings;
use crate::errors::call_optiga_func;
use crate::OptigaM;
use crate::OptigaStatus;
use crate::OID;

#[repr(u32)]
/// Types of cryptographic keys the Trust M is capable of storing and using.
pub enum ECCKeyTypes {
    Brainpoolp256R1 = cbindings::optiga_ecc_curve_OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1,
    Brainpoolp384R1 = cbindings::optiga_ecc_curve_OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1,
    Brainpool512R1 = cbindings::optiga_ecc_curve_OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1,
    Nistp256 = cbindings::optiga_ecc_curve_OPTIGA_ECC_CURVE_NIST_P_256,
    Nistp384 = cbindings::optiga_ecc_curve_OPTIGA_ECC_CURVE_NIST_P_384,
    Nistp521 = cbindings::optiga_ecc_curve_OPTIGA_ECC_CURVE_NIST_P_521,
}

#[repr(u32)]
pub enum RSAKeyTypes {
    RSA1024 = cbindings::optiga_rsa_key_type_OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL,
    RSA2048 = cbindings::optiga_rsa_key_type_OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL,
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum ECCKeySlots {
    ECCSlot1 = OID::DevicePrikey1 as u32,
    ECCSlot2 = OID::DevicePrikey2 as u32,
    ECCSlot3 = OID::DevicePrikey3 as u32,
    ECCSlot4 = OID::DevicePrikey4 as u32,
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum RSAKeySlots {
    RSASlot1 = OID::DevicePrikeyRSA1 as u32,
    RSASlot2 = OID::DevicePrikeyRSA2 as u32,
}

/// This metadata struct is based on metadata handling in <https://github.com/Infineon/python-optiga-trust>
pub struct Metadata {
    execute: AccessCondition,
    change: AccessCondition,
    read: AccessCondition,
    max_size: usize,
    used_size: usize,
    lcso: ObjectLifeCycleState,
    algorithm: KeyType,
    key_usage: KeyUsage,
    reset_type: ResetType,
}

enum AccessCondition {}

enum KeyType {
    RSA(RSAKeyTypes),
    ECC(ECCKeyTypes),
}

#[repr(u8)]
#[derive(num_enum::IntoPrimitive)]
enum ObjectLifeCycleState {
    Creation = 0x01,
    Initialization = 0x03,
    Operational = 0x07,
    Termination = 0x0f,
}

struct KeyUsage {
    authentication: bool,
    encryption: bool,
    sign: bool,
    key_agreement: bool,
}

enum ResetType {
    Lcso(ObjectLifeCycleState),
    Flushing,
    RandomData,
}

impl OptigaM {
    /// Generates a public/private keypair, storing it's private key in the SE. Will replace existing keypair if one is present in noted key slot.
    pub fn get_keypair_ecc(
        &mut self,
        pair_type: ECCKeyTypes,
        slot: ECCKeySlots,
    ) -> Result<(), OptigaStatus> {
        let lib_crypt = crate::crypt_create();

        use crate::c_void;
        use core::ptr::{addr_of, addr_of_mut};

        let mut public_key: [u8; 100] = [0; 100];
        let mut public_key_len = public_key.len().try_into().unwrap();

        #[cfg(not(any(test, feature = "tester")))]
        defmt::trace!("setting metadata");

        let metadata: [u8; 8] = [0x20, 0x06, 0xD0, 0x01, 0x00, 0xD3, 0x01, 0x00];

        call_optiga_func(|| unsafe {
            cbindings::optiga_util_write_metadata(
                self.lib_util.as_ptr(),
                slot as u16,
                addr_of!(metadata) as *const u8,
                metadata.len().try_into().unwrap(),
            )
        })?;

        #[cfg(not(any(test, feature = "tester")))]
        defmt::trace!("generating keypair");

        call_optiga_func(|| unsafe {
            cbindings::optiga_crypt_ecc_generate_keypair(
                lib_crypt.as_ptr(),
                pair_type as u32,
                (cbindings::optiga_key_usage_OPTIGA_KEY_USAGE_SIGN
                    | cbindings::optiga_key_usage_OPTIGA_KEY_USAGE_AUTHENTICATION
                    | cbindings::optiga_key_usage_OPTIGA_KEY_USAGE_KEY_AGREEMENT)
                    .try_into()
                    .unwrap(),
                false as u8,
                addr_of!(slot) as *mut c_void,
                addr_of_mut!(public_key) as *mut u8,
                &mut public_key_len,
            )
        })?;

        assert!(public_key_len <= public_key.len().try_into().unwrap());

        crate::crypt_destroy(lib_crypt);

        Ok(())
    }
    pub fn get_keypair_rsa(
        &mut self,
        pair_type: RSAKeyTypes,
        slot: RSAKeySlots,
    ) -> Result<(), OptigaStatus> {
        Ok(())
    }

    // /// Attempts to retrieve an existing public/private keypair in a SE slot. Will generate a keypair if one is not already available.
    // pub fn get_keypair_ecc(&mut self, pair_type: KeyType, slot: KeySlot) {}
    // pub fn calculate_signature_ecdsa() -> Result<(), OptigaStatus> {}

    // pub fn calculate_signature_rsa() -> Result<(), OptigaStatus> {}

    // pub fn verify_signature_ecdsa() -> Result<(), OptigaStatus> {}

    // pub fn verify_signature_rsa() -> Result<(), OptigaStatus> {}

    // pub fn generate_keypair_ecdsa() -> Result<(), OptigaStatus> {}

    // pub fn generate_keypair_rsa() -> Result<(), OptigaStatus> {}
}

// reference impl https://github.com/Infineon/arduino-optiga-trust-m/blob/master/src/OPTIGATrustM.cpp#L1556=
// yubihsm for comparison: https://docs.rs/yubihsm/0.40.0/yubihsm/ecdh/enum.Algorithm.html
// and ed25519_dalek for comparison https://docs.rs/ed25519-dalek/latest/ed25519_dalek/
// implementing rustcrypto/signature verify and signmut for signatures
// might just use elliptic-curve ecdh
// https://docs.rs/elliptic-curve/latest/elliptic_curve/ecdh/index.html
//
// will use https://docs.rs/chacha20poly1305/latest/chacha20poly1305/ eventually
// reusing the key forever is probably fine so long as the nonce is always random
//
// may have to specifically make a mock for this library. which would be annoying.
