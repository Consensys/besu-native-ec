/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>

#include "openssl/include/openssl/ec.h"
#include "openssl/include/openssl/evp.h"

#include "constants.h"
#include "ec_key.h"
#include "ec_verify.h"
#include "utils.h"

struct verify_result p256_verify(const unsigned char *data_hash,
                                 const size_t data_hash_length,
                                 const char *signature_r_hex,
                                 const char *signature_s_hex,
                                 const unsigned char public_key_data[]) {
  static const uint8_t P256_PUBLIC_KEY_LENGTH = 64;
  return verify(data_hash, data_hash_length, signature_r_hex, signature_s_hex,
                public_key_data, "prime256v1", P256_PUBLIC_KEY_LENGTH);
}

struct verify_result verify(const unsigned char *data_hash,
                            const size_t data_hash_length,
                            const char *signature_r_hex,
                            const char *signature_s_hex,
                            const unsigned char public_key_data[],
                            const char *group_name, uint8_t public_key_len) {
  struct verify_result result = {.verified = GENERIC_ERROR,
                                 .error_message = {0}};

  EVP_PKEY *key = NULL;
  unsigned char *der_encoded_signature = NULL;
  EVP_PKEY_CTX *verify_context = NULL;

  if (create_public_key(&key, result.error_message, public_key_data,
                        public_key_len, group_name) != SUCCESS) {
    goto end;
  }

  int der_encoded_signature_len = 0;
  if (create_der_encoded_signature(
          &der_encoded_signature, &der_encoded_signature_len,
          result.error_message, signature_r_hex, signature_s_hex) != SUCCESS) {
    set_error_message(result.error_message, "Could not create signature: ");
    goto end;
  }

  if ((verify_context = EVP_PKEY_CTX_new(key, NULL)) == NULL) {
    set_error_message(result.error_message,
                      "Could not create a context for verifying: ");
    goto end;
  }

  if (EVP_PKEY_verify_init(verify_context) != SUCCESS) {
    set_error_message(result.error_message,
                      "Could not initialize a context for verifying: ");
    goto end;
  }

  // verify signature: 1 = successfully verified, 0 = not successfully verified,
  // < 0 = error
  result.verified =
      EVP_PKEY_verify(verify_context, der_encoded_signature,
                      der_encoded_signature_len, data_hash, data_hash_length);

  if (result.verified == 0) {
    snprintf(result.error_message, 256, "Signature not valid");
  } else if (result.verified < 0) {
    set_error_message(result.error_message,
                      "Error while verifying signature: ");
  }

end:
  OPENSSL_free(der_encoded_signature);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(verify_context);

  return result;
}

int create_der_encoded_signature(unsigned char **der_encoded_signature,
                                 int *der_encoded_signature_len,
                                 char *error_message,
                                 const char *signature_r_hex,
                                 const char *signature_s_hex) {
  int ret = FAILURE;
  ECDSA_SIG *signature = NULL;

  BIGNUM *signature_r = NULL;
  BIGNUM *signature_s = NULL;

  if (BN_hex2bn(&signature_r, signature_r_hex) == FAILURE) {
    set_error_message(error_message,
                      "Could not convert r of signature to BIGNUM: ");
    goto end_create_der_encoded_signature;
  }

  if (BN_hex2bn(&signature_s, signature_s_hex) == FAILURE) {
    set_error_message(error_message,
                      "Could not convert s of signature to BIGNUM: ");
    goto end_create_der_encoded_signature;
  }

  if ((signature = ECDSA_SIG_new()) == NULL) {
    set_error_message(error_message,
                      "Could not allocate signature structure: ");
    goto end_create_der_encoded_signature;
  }

  if (ECDSA_SIG_set0(signature, signature_r, signature_s) != SUCCESS) {
    set_error_message(error_message,
                      "Could not set r & s in signature struct: ");
    // have to be freed here, because they could not be added to signature,
    // so they will not be freed when the signature is freed
    BN_free(signature_r);
    BN_free(signature_s);
    goto end_create_der_encoded_signature;
  }

  if ((*der_encoded_signature_len =
           i2d_ECDSA_SIG(signature, der_encoded_signature)) < 0) {
    set_error_message(error_message,
                      "Could not encode signature to DER format: ");
    goto end_create_der_encoded_signature;
  }

  ret = SUCCESS;

end_create_der_encoded_signature:
  // if the signature_r & signature_s are successfully added to the signature,
  // the signature takes over the memory management and frees them when the
  // signature is freed
  if (signature != NULL) {
    ECDSA_SIG_free(signature);
  } else {
    BN_free(signature_r);
    BN_free(signature_s);
  }

  return ret;
}