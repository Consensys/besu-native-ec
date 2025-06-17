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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "openssl/include/openssl/ec.h"
#include "openssl/include/openssl/evp.h"

#include "openssl/include/openssl/ecdsa.h"
#include "openssl/include/openssl/obj_mac.h"
#include "openssl/include/openssl/bn.h"
#include "openssl/include/openssl/x509.h"

#include "besu_native_ec.h"
#include "constants.h"
#include "ec_key.h"
#include "ec_verify.h"
#include "utils.h"




// Cached EC_GROUP for P-256
static EC_GROUP *p256_group = NULL;

__attribute__((constructor))
static void init_p256_group() {
  if (p256_group == NULL) {
    p256_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP_set_asn1_flag(p256_group, OPENSSL_EC_NAMED_CURVE);
  }
}

struct verify_result p256_verify(const char data_hash[],
                                 const int data_hash_length,
                                 const char signature_r_hex[],
                                 const char signature_s_hex[],
                                 const char public_key_data[]) {
  static const uint8_t P256_PUBLIC_KEY_LENGTH = 64;

  return verify(data_hash, data_hash_length, signature_r_hex, signature_s_hex,
                public_key_data, P256_PUBLIC_KEY_LENGTH, "prime256v1",
                NID_X9_62_prime256v1, false);
}

struct verify_result p256_verify_malleable_signature(
    const char data_hash[], const int data_hash_length,
    const char signature_r_hex[], const char signature_s_hex[],
    const char public_key_data[]) {
  static const uint8_t P256_PUBLIC_KEY_LENGTH = 64;

  return verify(data_hash, data_hash_length, signature_r_hex, signature_s_hex,
                public_key_data, P256_PUBLIC_KEY_LENGTH, "prime256v1",
                NID_X9_62_prime256v1, true);
}

struct verify_result verify(const char data_hash[], const int data_hash_length,
                            const char signature_r_arr[],
                            const char signature_s_arr[],
                            const char public_key_data[], int public_key_len,
                            const char *group_name, int curve_nid,
                            bool allow_malleable_signature) {
  struct verify_result result = {.verified = GENERIC_ERROR,
                                 .error_message = {0}};

 // call constructor explicitly, just in case
 init_p256_group();

  EC_KEY *ec_key = NULL;
  EC_POINT *pub_point = NULL;
  EVP_PKEY *evp_key = NULL;
  ECDSA_SIG *sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  char *r_str = NULL, *s_str = NULL;

  if (!allow_malleable_signature &&
      is_signature_canonicalized(signature_s_arr, public_key_len / 2, curve_nid,
                                  result.error_message) != 1) {
    set_error_message(result.error_message,
                      "Signature is not canonicalized. s of signature must not be greater than n / 2: ");
    goto end;
  }

  r_str = hex_arr_to_str(signature_r_arr, public_key_len / 2);
  s_str = hex_arr_to_str(signature_s_arr, public_key_len / 2);
  if (!BN_hex2bn(&r, r_str) || !BN_hex2bn(&s, s_str)) {
    set_error_message(result.error_message, "Failed to parse r or s from hex");
    goto end;
  }

  sig = ECDSA_SIG_new();
  if (!ECDSA_SIG_set0(sig, r, s)) {
    set_error_message(result.error_message, "Failed to set r/s in signature");
    BN_free(r); BN_free(s);
    goto end;
  }
  r = s = NULL; // ownership transferred

  if (public_key_len == 64) {
    ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, p256_group);

    pub_point = EC_POINT_new(p256_group);
    unsigned char full_key[65];
    full_key[0] = 0x04;
    memcpy(&full_key[1], public_key_data, 64);

    if (!EC_POINT_oct2point(p256_group, pub_point, full_key, 65, NULL) ||
        !EC_KEY_set_public_key(ec_key, pub_point)) {
      set_error_message(result.error_message, "Failed to parse 64-byte public key");
      goto end;
    }
  } else if (public_key_len == 65 && public_key_data[0] == 0x04) {
    ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, p256_group);
    pub_point = EC_POINT_new(p256_group);

    if (!EC_POINT_oct2point(p256_group, pub_point, (unsigned char *)public_key_data, 65, NULL) ||
        !EC_KEY_set_public_key(ec_key, pub_point)) {
      set_error_message(result.error_message, "Failed to parse 65-byte SEC1 public key");
      goto end;
    }
  } else {
    const unsigned char *key_ptr = (const unsigned char *)public_key_data;
    evp_key = d2i_PUBKEY(NULL, &key_ptr, public_key_len);
    if (evp_key == NULL || (ec_key = EVP_PKEY_get1_EC_KEY(evp_key)) == NULL) {
      set_error_message(result.error_message, "Failed to decode ASN.1/DER public key");
      goto end;
    }
  }

  result.verified = ECDSA_do_verify((const unsigned char *)data_hash, data_hash_length, sig, ec_key);
  if (result.verified < 0) {
    set_error_message(result.error_message, "ECDSA_do_verify() failed");
  }

end:
  free(r_str);
  free(s_str);
  ECDSA_SIG_free(sig);
  EC_POINT_free(pub_point);
  EC_KEY_free(ec_key);
  EVP_PKEY_free(evp_key);
  BN_free(r);
  BN_free(s);

  return result;
}

int is_signature_canonicalized(const char signature_s_arr[],
                               const int signature_arr_len, const int curve_nid,
                               char *error_message) {
  int ret = GENERIC_ERROR;

  BIGNUM *s = NULL;
  BIGNUM *n = NULL;      // curve order
  BIGNUM *n_half = NULL; // half curve order

  if ((n = get_curve_order(curve_nid, error_message)) == NULL) {
    goto end_is_signature_canonicalized;
  }

  if ((n_half = BN_new()) == NULL) {
    set_error_message(error_message,
                      "Could not allocate memory to store curve order: ");
    goto end_is_signature_canonicalized;
  }

  // shift n right by 1 byte, which equals a division by 2
  if (BN_rshift1(n_half, n) != SUCCESS) {
    set_error_message(error_message,
                      "Could not calculate the half curve order: ");
    goto end_is_signature_canonicalized;
  }

  if ((s = BN_bin2bn((const unsigned char *)signature_s_arr, signature_arr_len,
                     s)) == NULL) {
    set_error_message(error_message,
                      "Could not convert s of signature to BIGNUM: ");
    goto end_is_signature_canonicalized;
  }

  // if BN_cmp returns 1 it means s is greater than n_half,
  // this means it is NOT canonicalized
  ret = BN_cmp(s, n_half) != 1;

end_is_signature_canonicalized:
  BN_free(s);
  BN_free(n);
  BN_free(n_half);

  return ret;
}

int create_der_encoded_signature(unsigned char **der_encoded_signature,
                                 int *der_encoded_signature_len,
                                 char *error_message,
                                 const char signature_r_arr[],
                                 const char signature_s_arr[],
                                 int signature_arr_len) {
  int ret = FAILURE;
  ECDSA_SIG *signature = NULL;

  BIGNUM *signature_r = NULL;
  BIGNUM *signature_s = NULL;
  char *signature_r_str = hex_arr_to_str(signature_r_arr, signature_arr_len);
  char *signature_s_str = hex_arr_to_str(signature_s_arr, signature_arr_len);

  if (BN_hex2bn(&signature_r, signature_r_str) == FAILURE) {
    set_error_message(error_message,
                      "Could not convert r of signature to BIGNUM: ");
    goto end_create_der_encoded_signature;
  }

  if (BN_hex2bn(&signature_s, signature_s_str) == FAILURE) {
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
  free(signature_r_str);
  free(signature_s_str);

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
