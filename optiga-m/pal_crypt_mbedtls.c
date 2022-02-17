/**
* \copyright
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
* \endcopyright
*
* \author Infineon Technologies AG
*
* \file pal_crypt_mbedtls.c
*
* \brief   This file implements the platform abstraction layer APIs for cryptographic functions using mbedTLS SW Crypto.
*
* \ingroup  grPAL
*
* @{
*/

#include "optiga_lib_common.h"
#include "pal_crypt.h"
#include "pal_os_memory.h"

//lint --e{818, 715, 830} suppress "argument "p_pal_crypt" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_tls_prf_sha256(pal_crypt_t* p_pal_crypt,
                                      const uint8_t * p_secret,
                                      uint16_t secret_length,
                                      const uint8_t * p_label,
                                      uint16_t label_length,
                                      const uint8_t * p_seed,
                                      uint16_t seed_length,
                                      uint8_t * p_derived_key,
                                      uint16_t derived_key_length)
{
    return PAL_STATUS_SUCCESS;
}

//lint --e{818, 715, 830} suppress "argument "p_pal_crypt" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_encrypt_aes128_ccm(pal_crypt_t* p_pal_crypt,
                                          const uint8_t * p_plain_text,
                                          uint16_t plain_text_length,
                                          const uint8_t * p_encrypt_key,
                                          const uint8_t * p_nonce,
                                          uint16_t nonce_length,
                                          const uint8_t * p_associated_data,
                                          uint16_t associated_data_length,
                                          uint8_t mac_size,
                                          uint8_t * p_cipher_text)
{
    return PAL_STATUS_SUCCESS;
}

//lint --e{818, 715, 830} suppress "argument "p_pal_crypt" is not used in the implementation but kept for future use"
pal_status_t pal_crypt_decrypt_aes128_ccm(pal_crypt_t* p_pal_crypt,
                                          const uint8_t * p_cipher_text,
                                          uint16_t cipher_text_length,
                                          const uint8_t * p_decrypt_key,
                                          const uint8_t * p_nonce,
                                          uint16_t nonce_length,
                                          const uint8_t * p_associated_data,
                                          uint16_t associated_data_length,
                                          uint8_t mac_size,
                                          uint8_t * p_plain_text)
{
    return PAL_STATUS_SUCCESS;
}

pal_status_t pal_crypt_version(uint8_t * p_crypt_lib_version_info, uint16_t * length)
{
    return PAL_STATUS_SUCCESS;
}

/**
* @}
*/
