PATHU = unity/src/
PATHS = src/
PATHT = test/
PATHB = build/
PATHO = build/objs/
PATHR = build/results/
PATHL = build/libs/
PATHRE = release/
PATHRO = build/release/objs/
PATH_OPENSSL = openssl/
PATH_OPENSSL_INCLUDE = openssl/include/

ifeq ($(OS),Windows_NT)
  ifeq ($(shell uname -s),) # not in a bash-like shell
	CLEANUP = del /F /Q
	MKDIR = mkdir
	COPY = copy
  else # in a bash-like shell, like msys
	CLEANUP = rm -f
	MKDIR = mkdir -p
  endif
	TEST_EXTENSION=exe
	LIBRARY_EXTENSION=dll
else
	CLEANUP = rm -f
	MKDIR = mkdir -p
	COPY = cp
	TEST_EXTENSION=out
	ifeq ($(shell uname -s),Darwin) # on MacOS
		LIBRARY_EXTENSION=dylib
		OPENSSL_LIB_CRYPTO=$(PATH_OPENSSL)libcrypto.3.$(LIBRARY_EXTENSION)
	else # on Linux
		LIBRARY_EXTENSION=so
		OPENSSL_LIB_CRYPTO=$(PATH_OPENSSL)libcrypto.$(LIBRARY_EXTENSION).3
	endif
endif

.PHONY: clean
.PHONY: test

# libcrypto from OpenSSL will be renamed to this, to avoid naming conflicts
CRYPTO_LIB=besu_native_ec_crypto
CRYPTO_LIB_PATH=$(PATHL)lib$(CRYPTO_LIB).$(LIBRARY_EXTENSION)

BUILD_PATHS = $(PATHB) $(PATHO) $(PATHR) ${PATHL}

SRCT = $(wildcard $(PATHT)*.c)

COMPILE=gcc -c -Wall -Werror -std=c11 -O3 -fPIC

# this is used in the tests to find the local copy of the crypto library
LINK_TEST=gcc -L$(PATHL) -Wl,-rpath $(PATHL)
# this is used for the  besu_native_ec library release. The crypto library will be in the same folder as it,
# because they are shipped later in a jar file together
LINK_RELEASE=gcc -L$(PATHL) -Wl,-rpath ./
COMPILE_FLAGS=-I. -I$(PATHU) -I$(PATHS) -I$(PATH_OPENSSL_INCLUDE) -DTEST

# the following commands are used to create the console output of the tests
RESULTS = $(patsubst $(PATHT)test_%.c,$(PATHR)test_%.txt,$(SRCT) )

PASSED = `grep -s PASS $(PATHR)*.txt`
FAIL = `grep -s FAIL $(PATHR)*.txt`
IGNORE = `grep -s IGNORE $(PATHR)*.txt`

test: $(BUILD_PATHS) $(RESULTS) $(CRYPTO_LIB_PATH)
	@echo "-----------------------\nIGNORES:\n-----------------------"
	@echo "$(IGNORE)"
	@echo "-----------------------\nFAILURES:\n-----------------------"
	@echo "$(FAIL)"
	@echo "-----------------------\nPASSED:\n-----------------------"
	@echo "$(PASSED)"
	@echo "\nDONE"

	./check_failing_test.sh

# the result files are created by executing the tests and writing all their output into it
$(PATHR)%.txt: $(PATHB)%.$(TEST_EXTENSION)
	-./$< > $@ 2>&1

# the sign test uses the verification and key recovery as well, therefore those are added to its dependencies
$(PATHB)test_ec_sign.$(TEST_EXTENSION): $(CRYPTO_LIB_PATH) $(PATHO)test_ec_sign.o $(PATHO)ec_sign.o $(PATHO)ec_verify.o $(PATHO)ec_key_recovery.o $(PATHU)unity.o $(PATHO)constants.o $(PATHO)utils.o $(PATHO)ec_key.o
	$(LINK_TEST) -Wl,-rpath $(PATHL) $(CFLAGS) -o $@ $^ -l$(CRYPTO_LIB) -lc

# the other test don't have other dependencies and are compiled an their own
$(PATHB)test_%.$(TEST_EXTENSION): $(CRYPTO_LIB_PATH) $(PATHO)test_%.o $(PATHO)%.o $(PATHU)unity.o $(PATHO)constants.o $(PATHO)utils.o $(PATHO)ec_key.o
	$(LINK_TEST) -Wl,-rpath $(PATHL) $(CFLAGS) -o $@ $^ -l$(CRYPTO_LIB) -lc

# creates the test object files from the test *.c files
$(PATHO)%.o:: $(PATHT)%.c
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

# creates the object file from the *.c files in src/
$(PATHO)%.o:: $(PATHS)%.c
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

# creates the object files from the unity (test framework) files
$(PATHO)%.o:: $(PATHU)%.c $(PATHU)%.h
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

# the following commands create the directories of the build folder
$(PATHB):
	$(MKDIR) $(PATHB)

$(PATHO):
	$(MKDIR) $(PATHO)

$(PATHR):
	$(MKDIR) $(PATHR)

$(PATHRE):
	$(MKDIR) $(PATHRE)

$(PATHRO):
	$(MKDIR) $(PATHRO)

$(PATHL):
	$(MKDIR) $(PATHL)

# the crypto library from OpenSSL is copied and renamed
$(CRYPTO_LIB_PATH): $(PATHL)
	$(COPY) $(OPENSSL_LIB_CRYPTO) $@
# renaming a shared library is not enough. It's name/path is part of the file itself and encoded within it.
# For Linux it is enough to change the soname (id) to the new file name, as Linux will search in
# various directories for it
ifeq ($(shell uname -s),Linux)
	patchelf --set-soname lib$(CRYPTO_LIB).$(LIBRARY_EXTENSION) $@
endif
# Mac OS will look for the library only in the path that is defined in id. We change it using the variable rpath at
# the beginning and adding the file name afterwards. The value for rpath is defined in $LINK_TEST and $LINK_RELEASE
# respectively, when the test and the besu_native library are linked
#
# More details about native library resolution on Mac OS can be found here:
# https://medium.com/@donblas/fun-with-rpath-otool-and-install-name-tool-e3e41ae86172
ifeq ($(shell uname -s),Darwin)
	install_name_tool -id "@rpath/lib$(CRYPTO_LIB).$(LIBRARY_EXTENSION)" $@
endif

# the release build is created without debugging symbols and copied to the folder release/
release_build: $(PATHRO)constants.o $(PATHRO)ec_key.o $(PATHRO)ec_key_recovery.o $(PATHRO)ec_sign.o $(PATHRO)ec_verify.o $(PATHRO)utils.o
	$(COPY) $(CRYPTO_LIB_PATH) $(PATHRE)
	$(LINK_RELEASE) -Wl,-rpath ./ $^ -l$(CRYPTO_LIB) -fPIC -shared $(CFLAGS) -o $(PATHRE)libbesu_native_ec.$(LIBRARY_EXTENSION)
	$(COPY) src/besu_native_ec.h $(PATHRE)

$(PATHRO)%.o: $(PATHS)%.c $(PATHRO) $(PATHRE)
	$(COMPILE) $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

clean:
	$(CLEANUP) $(PATHO)*.o
	$(CLEANUP) $(PATHRO)*.o
	$(CLEANUP) $(PATHB)*.$(TEST_EXTENSION)
	$(CLEANUP) $(PATHR)*.txt
	$(CLEANUP) $(PATHRE)*.$(LIBRARY_EXTENSION) $(PATHRE)*.h
	$(CLEANUP) $(PATHL)*.*

.PRECIOUS: $(PATHB)test_%.$(TEST_EXTENSION)
.PRECIOUS: $(PATHO)%.o
.PRECIOUS: $(PATHR)%.txt
