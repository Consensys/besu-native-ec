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
#include <openssl/include/openssl/ec.h>

#include "besu_native_ec.h"
#include "constants.h"
#include "ec_key.h"
#include "ec_key_recovery.h"
#include "ec_sign.h"
#include "utils.h"

struct sign_result p256_sign(const char data_hash[], const int data_hash_length,
                             const char private_key_data[],
                             const char public_key_data[]) {
  static const uint8_t P256_PRIVATE_KEY_LENGTH = 32;
  static const uint8_t P256_PUBLIC_KEY_LENGTH = 64;

  return sign(data_hash, data_hash_length, private_key_data,
              P256_PRIVATE_KEY_LENGTH, public_key_data, P256_PUBLIC_KEY_LENGTH,
              "prime256v1", NID_X9_62_prime256v1);
}

struct sign_result sign(const char data_hash[], const int data_hash_len,
                        const char private_key_data[], int private_key_len,
                        const char public_key_data[], int public_key_len,
                        const char *group_name, int curve_nid) {
  struct sign_result result = {.signature_r = {0},
                               .signature_s = {0},
                               .signature_v = -1,
                               .error_message = {0}};

  EVP_PKEY *key = NULL;
  ECDSA_SIG *signature = NULL;
  char *signature_r = NULL;
  char *signature_s = NULL;
  int signature_len = private_key_len;

  if (signature_len >= MAX_SIGNATURE_BUFFER_LEN) {
    set_error_message(result.error_message,
                      "Signatures are too long for their buffers: ");
    goto end;
  }

  signature_r = OPENSSL_malloc(signature_len);
  signature_s = OPENSSL_malloc(signature_len);

  if (create_key_pair(&key, result.error_message,
                      (const unsigned char *)private_key_data, private_key_len,
                      (const unsigned char *)public_key_data, public_key_len,
                      group_name) != SUCCESS) {
    goto end;
  }

  if ((signature = create_signature(key, result.error_message,
                                    (const unsigned char *)data_hash,
                                    data_hash_len)) == NULL) {
    goto end;
  }

  if (canonicalize_signature(signature, result.error_message, curve_nid) !=
      SUCCESS) {
    goto end;
  }

  if (signature_to_bin_values(signature, result.error_message, &signature_r,
                              &signature_s, signature_len) != SUCCESS) {
    goto end;
  }

  // private key length and curve byte length are the same
  if (calculate_signature_v(&result, data_hash, data_hash_len, signature_r,
                            signature_s, public_key_data, public_key_len,
                            private_key_len, curve_nid) != SUCCESS) {
    goto end;
  }

  memcpy(result.signature_r, signature_r, signature_len);
  memcpy(result.signature_s, signature_s, signature_len);

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

int canonicalize_signature(const ECDSA_SIG *signature, char *error_message,
                           const int curve_nid) {
  int ret = GENERIC_ERROR;

  const BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  BIGNUM *n = NULL;      // curve order
  BIGNUM *n_half = NULL; // half curve order

  if ((n = get_curve_order(curve_nid, error_message)) == NULL) {
    goto end_canonicalize_signature;
  }

  if ((n_half = BN_new()) == NULL) {
    set_error_message(error_message,
                      "Could not allocate memory to store curve order: ");
    goto end_canonicalize_signature;
  }

  // shift n right by 1 byte, which equals a division by 2
  if (BN_rshift1(n_half, n) != SUCCESS) {
    set_error_message(error_message,
                      "Could not calculate the half curve order: ");
    goto end_canonicalize_signature;
  }

  ECDSA_SIG_get0(signature, &r, (const BIGNUM **)&s);

  // Allowing transactions with any s value with 0 < s < n, opens a
  // transaction malleability concern, as one can take any transaction,
  // flip the s value from s to n - s, flip the v value (27 -> 28, 28 -> 27),
  // and the resulting signature would still be valid. Therefore EIP-2 defined
  // that only s values lesser than n / s are valid.
  if (BN_cmp(s, n_half) == 1) {
    if (BN_sub(s, n, s) != SUCCESS) {
      set_error_message(
          error_message,
          "Could not subtract s from n to create a canonicalized signature: ");
      goto end_canonicalize_signature;
    }
  }

  ret = SUCCESS;

end_canonicalize_signature:
  BN_free(n);
  BN_free(n_half);

  return ret;
}

int signature_to_bin_values(const ECDSA_SIG *signature, char *error_message,
                            char **signature_r, char **signature_s,
                            const int signature_len) {
  int ret = GENERIC_ERROR;

  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;
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

  if (BN_bn2binpad(r, (unsigned char *)*signature_r, signature_len) ==
      GENERIC_ERROR) {
    set_error_message(error_message,
                      "Could not convert r into its big-endian form: ");
    goto end_signature_to_hex_values;
  }

  if (BN_bn2binpad(s, (unsigned char *)*signature_s, signature_len) ==
      GENERIC_ERROR) {
    set_error_message(error_message,
                      "Could not convert s into its big-endian form: ");
    goto end_signature_to_hex_values;
  }

  ret = SUCCESS;

end_signature_to_hex_values:

  return ret;
}

int calculate_signature_v(struct sign_result *result, const char data_hash[],
                          const size_t data_hash_len, const char signature_r[],
                          const char signature_s[],
                          const char public_key_data[], uint8_t public_key_len,
                          uint8_t curve_byte_len, int curve_nid) {
  int ret = FAILURE;

  for (int i = 0; i < 2; i++) {
    struct key_recovery_result recovery_result =
        key_recovery(data_hash, data_hash_len, signature_r, signature_s, i,
                     curve_nid, curve_byte_len);

    if (strlen(recovery_result.error_message) != 0) {
      set_error_message(result->error_message, recovery_result.error_message);
      goto end_calculate_signature_v;
    }

    if (memcmp(public_key_data, recovery_result.public_key, public_key_len) ==
        0) {
      result->signature_v = (signed char)i;
      break;
    }
  }

  if (result->signature_v == -1) {
    set_error_message(result->error_message,
                      "Could not determine signature_v: ");
    goto end_calculate_signature_v;
  }

  ret = SUCCESS;

end_calculate_signature_v:

  return ret;
}
