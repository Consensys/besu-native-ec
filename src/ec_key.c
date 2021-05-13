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
#include <stdlib.h>
#include <string.h>

#include "openssl/include/openssl/core_names.h"
#include "openssl/include/openssl/ec.h"

#include "constants.h"
#include "ec_key.h"
#include "utils.h"

int create_key_pair(EVP_PKEY **key, char *error_message,
                    const unsigned char private_key_data[],
                    uint8_t private_key_len,
                    const unsigned char public_key_data[],
                    uint8_t public_key_len, const char *group_name) {
  unsigned char *public_key_buffer = malloc(public_key_len + 1);
  OSSL_PARAM_BLD *param_bld = generate_public_key_param(
      public_key_data, public_key_len, public_key_buffer);

  BIGNUM *private_key = BN_bin2bn(private_key_data, private_key_len, NULL);
  OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, private_key);

  int ret = create_key(key, error_message, group_name, param_bld);

  free(public_key_buffer);
  BN_free(private_key);

  return ret;
}

int create_public_key(EVP_PKEY **key, char *error_message,
                      const unsigned char public_key_data[],
                      uint8_t public_key_len, const char *group_name) {
  unsigned char *public_key_buffer = malloc(public_key_len + 1);
  OSSL_PARAM_BLD *param_bld = generate_public_key_param(
      public_key_data, public_key_len, public_key_buffer);

  int ret = create_key(key, error_message, group_name, param_bld);

  free(public_key_buffer);
  return ret;
}

int create_key(EVP_PKEY **key, char *error_message, const char *group_name,
               OSSL_PARAM_BLD *param_bld) {
  int ret = FAILURE;

  EVP_PKEY_CTX *key_context = NULL;
  OSSL_PARAM *params = NULL;

  OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                  group_name, 0);

  if ((params = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
    set_error_message(error_message,
                      "Could not create parameters for key operation: ");
    goto end_create_key;
  }

  if ((key_context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL) {
    set_error_message(error_message,
                      "Could not allocate memory for key context: ");
    goto end_create_key;
  }

  if (EVP_PKEY_fromdata_init(key_context) != SUCCESS) {
    set_error_message(error_message,
                      "Could not initializes a context for key import: ");
    goto end_create_key;
  }

  if (EVP_PKEY_fromdata(key_context, key, EVP_PKEY_KEYPAIR, params) !=
      SUCCESS) {
    set_error_message(error_message,
                      "Could not create structure to store public key: ");
    goto end_create_key;
  }

  ret = SUCCESS;

end_create_key:
  EVP_PKEY_CTX_free(key_context);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(param_bld);

  return ret;
}

OSSL_PARAM_BLD *generate_public_key_param(const unsigned char public_key_data[],
                                          uint8_t public_key_len,
                                          unsigned char *public_key_buffer) {
  public_key_buffer[0] = POINT_CONVERSION_UNCOMPRESSED;
  memcpy((void *)(public_key_buffer + 1), public_key_data, public_key_len);

  OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                   public_key_buffer, public_key_len + 1);

  return param_bld;
}