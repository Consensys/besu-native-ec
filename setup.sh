#!/bin/bash

if [[ "$OSTYPE" == "msys" ]]; then
	LIBRARY_EXTENSION=dll
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  LIBRARY_EXTENSION=so
elif [[ "$OSTYPE" == "darwin"* ]]; then
  LIBRARY_EXTENSION=dylib
fi

git submodule init
git submodule update

cd openssl
./Configure enable-ec_nistp_64_gcc_128 no-stdio no-ocsp no-nextprotoneg no-module \
            no-legacy no-gost no-engine no-dynamic-engine no-deprecated no-comp \
            no-cmp no-capieng no-ui-console no-tls no-ssl no-dtls no-aria no-bf \
            no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa \
            no-ecdh no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 \
            no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool
make build_generated libcrypto.$LIBRARY_EXTENSION

cd ../