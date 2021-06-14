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
#include <string.h>

#include "openssl/include/openssl/asn1.h"
#include "openssl/include/openssl/ec.h"
#include "openssl/include/openssl/obj_mac.h"

#include "besu_native_ec.h"
#include "constants.h"
#include "ec_key_recovery.h"
#include "utils.h"

struct key_recovery_result p256_key_recovery(const char data_hash[],
                                             const int data_hash_len,
                                             const char signature_r[],
                                             const char signature_s[],
                                             const int signature_v) {
  unsigned int CURVE_BYTE_LENGTH = 32;
  return key_recovery(data_hash, data_hash_len, signature_r, signature_s,
                      signature_v, NID_X9_62_prime256v1, CURVE_BYTE_LENGTH);
}

// Given the components of a signature and a selector value, recover and return
// the public key that generated the signature according to the algorithm in
// SEC1v2 section 4.1.6.
//
// http://www.secg.org/sec1-v2.pdf
struct key_recovery_result key_recovery(const char data_hash[],
                                        int data_hash_len,
                                        const char signature_r_arr[],
                                        const char signature_s_arr[],
                                        int signature_v, const int curve_nid,
                                        const int curve_byte_length) {
  struct key_recovery_result result = {.public_key = {0}, .error_message = {0}};

  EC_GROUP *group = NULL;
  const BIGNUM *n = NULL; // curve order
  BIGNUM *r = NULL, *x = NULL, *p = NULL, *e = NULL, *inverse_r = NULL,
         *s = NULL;
  BN_CTX *bn_context = NULL;
  EC_POINT *R = NULL, *nR = NULL, *sR = NULL, *negative_eG = NULL,
           *sR_minus_eG = NULL, *Q = NULL;
  char *Q_octet = NULL;

  int signature_arr_len = curve_byte_length;
  char *signature_r_str = hex_arr_to_str(signature_r_arr, signature_arr_len);
  char *signature_s_str = hex_arr_to_str(signature_s_arr, signature_arr_len);

  if (signature_v != 0 && signature_v != 1 && signature_v != 27 &&
      signature_v != 28) {
    set_error_message(result.error_message,
                      "signature_v must be either 0, 1, 27 or 28: ");
    goto end;
  }

  // Ethereum transactions use 27 or 28 as valid values for v. We have to
  // convert them to 0 or 1 internally
  if (signature_v == 27 || signature_v == 28) {
    signature_v -= 27;
  }

  // if data_hash is longer than the curve byte length, we only consider the
  // left most curve_byte_length bytes of it
  if (data_hash_len > curve_byte_length) {
    data_hash_len = curve_byte_length;
  }

  if ((group = EC_GROUP_new_by_curve_name(curve_nid)) == NULL) {
    set_error_message(result.error_message,
                      "Could not get EC_GROUP for requested curve: ");
    goto end;
  }

  if ((bn_context = BN_CTX_new()) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for BIGNUM context: ");
    goto end;
  }

  if ((p = BN_new()) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for BIGNUM p: ");
    goto end;
  }
  if (EC_GROUP_get_curve(group, p, NULL, NULL, bn_context) != SUCCESS) {
    set_error_message(result.error_message,
                      "Could not get prime of selected curve ");
    goto end;
  }

  // returns the internal pointer of the curve order, which will be freed
  // automatically by calling EC_GROUP_free
  if ((n = EC_GROUP_get0_order(group)) == NULL) {
    set_error_message(result.error_message,
                      "Could not convert curve order (n) to BIGNUM: ");
    goto end;
  }

  if (BN_hex2bn(&r, signature_r_str) == FAILURE) {
    set_error_message(result.error_message,
                      "Could not convert r of signature to BIGNUM: ");
    goto end;
  }

  // 1.1. Let x = r + j * n
  // In our case the cofactor of the curve is 1. In such curves j is always 0,
  // therefore we can simplify the equation to x = r
  x = r;

  // 1.2. Convert the integer x to an octet string X of length mlen using the
  // conversion routine specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or
  // mlen = ⌈m/8⌉. 1.3. Convert the octet string (16 set binary digits)||X to an
  // elliptic curve point R using the conversion routine specified in
  // Section 2.3.4. If this conversion routine outputs "invalid", then do
  // another iteration of Step 1.
  if ((R = EC_POINT_new(group)) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for point R: ");
    goto end;
  }
  if (EC_POINT_set_compressed_coordinates(group, R, x, signature_v,
                                          bn_context) != SUCCESS) {
    set_error_message(result.error_message,
                      "Could not set compressed coordinates for point R: ");
    goto end;
  }

  // 1.4. If nR != point at infinity, then do another iteration of Step 1
  if ((nR = EC_POINT_new(group)) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for point nR: ");
    goto end;
  }
  if (EC_POINT_mul(group, nR, NULL, R, n, bn_context) != SUCCESS) {
    set_error_message(result.error_message,
                      "Could not multiply curve point R with curve order n: ");
    goto end;
  }
  if (!EC_POINT_is_at_infinity(group, nR)) {
    set_error_message(result.error_message,
                      "Point nR should be at infinity, but is not: ");
    goto end;
  }

  // 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
  if ((e = BN_bin2bn((const unsigned char *)data_hash, data_hash_len, NULL)) ==
      NULL) {
    set_error_message(result.error_message,
                      "Could not convert data hash to BIGNUM: ");
    goto end;
  }

  // 1.6. For k from 1 to 2 do the following. (loop is outside this function)
  // 1.6.1. Compute a candidate public key as:
  // Q = r^-1 * (s * R - e * G)

  // r^⁻1
  if ((inverse_r = BN_mod_inverse(NULL, r, n, bn_context)) == NULL) {
    set_error_message(result.error_message,
                      "Could not calculate the inverse of r: ");
    goto end;
  }

  // s * R
  if (BN_hex2bn(&s, signature_s_str) == FAILURE) {
    set_error_message(result.error_message,
                      "Could not convert s of signature to BIGNUM: ");
    goto end;
  }
  if ((sR = EC_POINT_new(group)) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for point sR: ");
    goto end;
  }
  if (EC_POINT_mul(group, sR, NULL, R, s, bn_context) != SUCCESS) {
    set_error_message(result.error_message,
                      "Could not multiply curve point R with signature s: ");
    goto end;
  }

  // -e * G
  BN_set_negative(e, 1);
  if ((negative_eG = EC_POINT_new(group)) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for point eG: ");
    goto end;
  }
  if (EC_POINT_mul(group, negative_eG, e, NULL, NULL, bn_context) != SUCCESS) {
    set_error_message(result.error_message,
                      "Could not multiply curve point R with signature s: ");
    goto end;
  }

  // sR + (-eG)
  if ((sR_minus_eG = EC_POINT_new(group)) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for point sR_minus_eG: ");
    goto end;
  }
  if (EC_POINT_add(group, sR_minus_eG, sR, negative_eG, bn_context) !=
      SUCCESS) {
    set_error_message(result.error_message,
                      "Could not calculate point sR_minus_eG: ");
    goto end;
  }

  // Q = r^⁻1 * (sR - eG)
  if ((Q = EC_POINT_new(group)) == NULL) {
    set_error_message(result.error_message,
                      "Could not allocate memory for point Q: ");
    goto end;
  }
  if (EC_POINT_mul(group, Q, NULL, sR_minus_eG, inverse_r, bn_context) !=
      SUCCESS) {
    set_error_message(result.error_message,
                      "Could not multiply curve point sR_minus_eG with r^⁻1: ");
    goto end;
  }

  int Q_octet_len = 0;
  point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
  if ((Q_octet_len = EC_POINT_point2oct(group, Q, form, NULL, 0, bn_context)) ==
      0) {
    set_error_message(
        result.error_message,
        "Could determine the buffer size of the octet form of Q: ");
  }

  if (Q_octet_len >= MAX_PUBLIC_KEY_BUFFER_LEN) {
    set_error_message(result.error_message,
                      "Recovered public key is too long for its buffer: ");
    goto end;
  }

  Q_octet = OPENSSL_malloc(Q_octet_len);
  if (EC_POINT_point2oct(group, Q, form, (unsigned char *)Q_octet, Q_octet_len,
                         bn_context) == 0) {
    set_error_message(result.error_message,
                      "Could convert Q to its octet form: ");
    goto end;
  }

  // do not copy the first byte (two hex values), because it is always 0x04
  // to indicate that it is an uncompressed public key format
  const char *Q_octet_without_format_identifier = Q_octet + 1;
  memcpy(result.public_key, Q_octet_without_format_identifier, Q_octet_len - 1);

end:
  free(signature_r_str);
  free(signature_s_str);
  EC_GROUP_free(group);
  BN_CTX_free(bn_context);
  BN_free(p);
  BN_free(r);
  BN_free(s);
  BN_free(e);
  BN_free(inverse_r);
  EC_POINT_free(R);
  EC_POINT_free(nR);
  EC_POINT_free(negative_eG);
  EC_POINT_free(sR);
  EC_POINT_free(Q);
  EC_POINT_free(sR_minus_eG);
  OPENSSL_free(Q_octet);

  return result;
}