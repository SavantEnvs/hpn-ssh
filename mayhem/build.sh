#!/usr/bin/env bash
#
# hpn-ssh/mayhem/build.sh (mining layer for 8f3b180) — builds hpn-ssh as sanitized libFuzzer targets.
#
#   sshsig_principals_fuzz — sshsig.c's allowed_signers matching (sshsig_find_principals() and
#                    sshsig_check_allowed_keys()): the input is the principals/options part of the lines.
#
# The SSH library and sshsig.o are compiled with $SANITIZER_FLAGS so the fuzzed code is
# instrumented; the build contract (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/STANDALONE_FUZZ_MAIN)
# comes from the org base ENV.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DWARF < 4 independent of the sanitizer switch (§6.2 item 10); after SANITIZER_FLAGS so -gdwarf-3 wins.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${CFLAGS=}" ; : "${CXXFLAGS=}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX CFLAGS CXXFLAGS LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"
OUT=/mayhem

# -fsanitize=fuzzer-no-link instruments the SSH code with libFuzzer coverage counters without a main().
COV_FLAGS=""
[ -n "${SANITIZER_FLAGS}" ] && COV_FLAGS="-fsanitize=fuzzer-no-link"
export COV_FLAGS

# Skip configure+make if the tree is already built (a second offline run is a safe no-op).
if [ -f Makefile ] && [ -f libssh.a ] && [ -f sshsig.o ]; then
  echo ">> configure+make: tree already built — skipping (idempotent re-run)"
else
  autoreconf
  # 2021 autoconf probes call exit() without <stdlib.h>: clang 16+ errors on implicit declarations.
  # configure (generated, untracked) rejects OpenSSL 3.5: accept every 3.x like its "3.0 development" case.
  sed -i 's/^\([[:space:]]*\)300\*)/\130*)/' configure
  env CFLAGS="-Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion" ./configure \
      --without-hardening \
      --without-zlib-version-check \
      --with-cflags-after="$SANITIZER_FLAGS $COV_FLAGS" \
      --with-ldflags-after="-g $SANITIZER_FLAGS" \
    || { echo "------ config.log:" 1>&2; cat config.log 1>&2; echo "ERROR: configure failed" 1>&2; exit 1; }

  # Only the library and the objects the harness links: sshsig.o is ssh-keygen's, not in libssh.a.
  make -j"$MAYHEM_JOBS" libssh.a openbsd-compat/libopenbsd-compat.a sshsig.o ssh-pkcs11-client.o
fi

EXTRA_CFLAGS="-D_GNU_SOURCE -Iopenbsd-compat/include"
LINK_DEPS="sshsig.o ssh-pkcs11-client.o ssh-sk-null.o -lssh -lopenbsd-compat -lcrypto -lz"

STANDALONE_MAIN_SRC="${STANDALONE_FUZZ_MAIN:-/opt/mayhem/StandaloneFuzzTargetMain.c}"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_MAIN_SRC" -o "$SRC/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$SRC/lsan_off.o"
# Security-key (FIDO/U2F) support is stubbed out, so libfido2/libcbor are not needed.
$CXX $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -std=c++11 $EXTRA_CFLAGS -I. -c \
	regress/misc/fuzz-harness/ssh-sk-null.cc -o "$SRC/ssh-sk-null.o"

build_harness() {
  local name="$1"
  echo ">> building $name"
  $CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS -I. -c "mayhem/harnesses/$name.c" -o "$SRC/$name.o"
  # libFuzzer target
  $CXX $CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -L. -Lopenbsd-compat \
	"$SRC/$name.o" "$SRC/lsan_off.o" $LINK_DEPS -o "$OUT/$name" $LIB_FUZZING_ENGINE
  # standalone reproducer (one input file, runs once)
  $CXX $CXXFLAGS $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -L. -Lopenbsd-compat \
	"$SRC/$name.o" "$SRC/standalone_main.o" "$SRC/lsan_off.o" $LINK_DEPS -o "$OUT/$name-standalone" \
	|| echo "WARNING: standalone build for $name failed (libFuzzer target still produced)" >&2
}

build_harness sshsig_principals_fuzz

# Functional known-answer oracle (mayhem/test.sh runs it): built with $SANITIZER_FLAGS because it links
# the sanitized libssh.a and sshsig.o.
echo ">> building sshsig_principals_oracle"
$CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS -I. -c mayhem/harnesses/sshsig_principals_oracle.c -o "$SRC/sshsig_principals_oracle.o"
$CXX $CXXFLAGS $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -L. -Lopenbsd-compat \
	"$SRC/sshsig_principals_oracle.o" "$SRC/lsan_off.o" $LINK_DEPS -o "$SRC/mayhem-oracle"

echo "build.sh complete:"
ls -la "$OUT"/sshsig_principals_fuzz "$SRC"/mayhem-oracle
