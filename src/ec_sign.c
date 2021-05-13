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
#include <string.h>

#include "openssl/include/openssl/evp.h"

#include "constants.h"
#include "ec_key.h"
#include "ec_key_recovery.h"
#include "ec_sign.h"
#include "utils.h"

struct sign_result p256_sign(const unsigned char *data_hash,
                             const size_t data_hash_length,
                             const unsigned char private_key_data[],
                             const unsigned char public_key_data[]) {
  static const uint8_t P256_PRIVATE_KEY_LENGTH = 32;
  static const uint8_t P256_PUBLIC_KEY_LENGTH = 64;

  return sign(data_hash, data_hash_length, private_key_data,
              P256_PRIVATE_KEY_LENGTH, public_key_data, P256_PUBLIC_KEY_LENGTH,
              "prime256v1", NID_X9_62_prime256v1);
}

struct sign_result
sign(const unsigned char *data_hash, const size_t data_hash_len,
     const unsigned char private_key_data[], uint8_t private_key_len,
     const unsigned char public_key_data[], uint8_t public_key_len,
     const char *group_name, int curve_nid) {
  struct sign_result result = {.signature_r = {0},
                               .signature_s = {0},
                               .signature_v = -1,
                               .error_message = {0}};

  EVP_PKEY *key = NULL;
  ECDSA_SIG *signature = NULL;
  char *signature_r = NULL;
  char *signature_s = NULL;

  if (create_key_pair(&key, result.error_message, private_key_data,
                      private_key_len, public_key_data, public_key_len,
                      group_name) != SUCCESS) {
    goto end;
  }

  if ((signature = create_signature(key, result.error_message, data_hash,
                                    data_hash_len)) == NULL) {
    goto end;
  }

  if (signature_to_hex_values(signature, result.error_message, &signature_r,
                              &signature_s) != SUCCESS) {
    goto end;
  }

  // private key length and curve byte length are the same
  if (calculate_signature_v(&result, data_hash, data_hash_len, signature_r,
                            signature_s, public_key_data, public_key_len,
                            private_key_len, curve_nid) != SUCCESS) {
    goto end;
  }

  size_t signature_r_len = strlen(signature_r);
  if (signature_r_len >= MAX_SIGNATURE_BUFFER_LEN) {
    set_error_message(result.error_message,
                      "Created signature_r is too long for its buffer: ");
    goto end;
  }

  size_t signature_s_len = strlen(signature_s);
  if (signature_s_len >= MAX_SIGNATURE_BUFFER_LEN) {
    set_error_message(result.error_message,
                      "Created signature_s is too long for its buffer: ");
    goto end;
  }

  memcpy(result.signature_r, signature_r, signature_r_len + 1);
  memcpy(result.signature_s, signature_s, signature_s_len + 1);

end:
  EVP_PKEY_free(key);
  ECDSA_SIG_free(signature);
  OPENSSL_free(signature_r);
  OPENSSL_free(signature_s);

  return result;
}

ECDSA_SIG *create_signature(EVP_PKEY *key, char *error_message,
                            const unsigned char *data_hash,
                            const size_t data_hash_length) {
  ECDSA_SIG *signature = NULL;
  EVP_PKEY_CTX *sign_context = NULL;
  unsigned char *der_encoded_signature = NULL;

  if ((sign_context = EVP_PKEY_CTX_new(key, NULL)) == NULL) {
    set_error_message(error_message,
                      "Could not create a context for signing: ");
    goto end_create_signature;
  }

  if (EVP_PKEY_sign_init(sign_context) != SUCCESS) {
    set_error_message(error_message,
                      "Could not initialize a context for signing: ");
    goto end_create_signature;
  }

  // a call to EVP_PKEY_sign with signature = NULL, only determines how long the
  // maximum signature length will be and writes it to der_encoded_signature_len
  size_t der_encoded_signature_len = 0;
  if (EVP_PKEY_sign(sign_context, NULL, &der_encoded_signature_len, data_hash,
                    data_hash_length) != SUCCESS) {
    set_error_message(
        error_message,
        "Could not determine the length of the signature buffer: ");
    goto end_create_signature;
  }

  if ((der_encoded_signature = OPENSSL_malloc(der_encoded_signature_len)) ==
      NULL) {
    set_error_message(error_message,
                      "Could not allocate memory for signature buffer: ");
    goto end_create_signature;
  }

  // a call to EVP_PKEY_sign with a buffer for signature creates the signature
  // and sets der_encoded_signature_len to the actual size of the signature
  if (EVP_PKEY_sign(sign_context, der_encoded_signature,
                    &der_encoded_signature_len, data_hash,
                    data_hash_length) != SUCCESS) {
    set_error_message(error_message,
                      "Could not allocate memory for signature buffer: ");
    goto end_create_signature;
  }

  const unsigned char *p = der_encoded_signature;
  if ((signature = d2i_ECDSA_SIG(NULL, &p, der_encoded_signature_len)) ==
      NULL) {
    set_error_message(
        error_message,
        "Could not decode signature from DER encoding to internal one: ");
    goto end_create_signature;
  }

end_create_signature:
  EVP_PKEY_CTX_free(sign_context);
  OPENSSL_free(der_encoded_signature);

  return signature;
}

int signature_to_hex_values(const ECDSA_SIG *signature, char *error_message,
                            char **signature_r, char **signature_s) {
  int ret = GENERIC_ERROR;

  const BIGNUM *r = NULL, *s = NULL;
  ECDSA_SIG_get0(signature, &r, &s);

  if (r == NULL) {
    set_error_message(error_message,
                      "Could not get r value from created signature: ");
    goto end_signature_to_hex_values;
  }

  if (s == NULL) {
    set_error_message(error_message,
                      "Could not get s value from created signature: ");
    goto end_signature_to_hex_values;
  }

  if ((*signature_r = BN_bn2hex(r)) == NULL) {
    set_error_message(error_message,
                      "Could not convert r to its hex representation: ");
    goto end_signature_to_hex_values;
  }

  if ((*signature_s = BN_bn2hex(s)) == NULL) {
    set_error_message(error_message,
                      "Could not convert s to its hex representation: ");
    goto end_signature_to_hex_values;
  }

  ret = SUCCESS;

end_signature_to_hex_values:

  return ret;
}

int calculate_signature_v(struct sign_result *result,
                          const unsigned char *data_hash,
                          const size_t data_hash_len, const char *signature_r,
                          const char *signature_s,
                          const unsigned char public_key_data[],
                          uint8_t public_key_len, uint8_t curve_byte_len,
                          int curve_nid) {
  unsigned char *recovered_public_key_data = NULL;

  int ret = FAILURE;

  for (int i = 0; i < 2; i++) {
    struct key_recovery_result recovery_result =
        key_recovery(data_hash, data_hash_len, signature_r, signature_s, i,
                     curve_nid, curve_byte_len);

    if (strlen(recovery_result.error_message) != 0) {
      set_error_message(result->error_message, recovery_result.error_message);
      goto end_calculate_signature_v;
    }

    recovered_public_key_data = hex_to_bin(recovery_result.public_key);

    if (memcmp(public_key_data, recovered_public_key_data, public_key_len) ==
        0) {
      result->signature_v = i;
      break;
    }

    free(recovered_public_key_data);
    recovered_public_key_data = NULL;
  }

  if (result->signature_v == -1) {
    set_error_message(result->error_message,
                      "Could not determine signature_v: ");
    goto end_calculate_signature_v;
  }

  ret = SUCCESS;

end_calculate_signature_v:

  free(recovered_public_key_data);

  return ret;
}
