#!/usr/bin/env bash
#
# hpn-ssh/mayhem/build.sh (mining layer for 6500c3b) — builds hpn-ssh as sanitized libFuzzer targets.
#
#   hostfiles_fuzz — auth.c's check_key_in_hostfiles(): the input is a known_hosts file's contents.
#                    auth.c is sshd's, so the harness links sshd's objects (sshd.o with main renamed).
#
# The SSH library and sshd objects are compiled with $SANITIZER_FLAGS so the fuzzed code is
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
if [ -f Makefile ] && [ -f libssh.a ] && [ -f sshd.o ]; then
  echo ">> configure+make: tree already built — skipping (idempotent re-run)"
else
  autoreconf
  # 2019 autoconf probes call exit() without <stdlib.h>: clang 16+ errors on implicit declarations.
  # configure (generated, untracked) rejects OpenSSL 3.5: accept every 3.x like its "3.0 development" case.
  sed -i 's/^\([[:space:]]*\)300\*)/\130*)/' configure
  env CFLAGS="-Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion" ./configure \
      --without-hardening \
      --without-zlib-version-check \
      --with-cflags-after="$SANITIZER_FLAGS $COV_FLAGS" \
      --with-ldflags-after="-g $SANITIZER_FLAGS" \
    || { echo "------ config.log:" 1>&2; cat config.log 1>&2; echo "ERROR: configure failed" 1>&2; exit 1; }

  make -j"$MAYHEM_JOBS" all
fi

EXTRA_CFLAGS="-D_GNU_SOURCE -Iopenbsd-compat/include"

# sshd.o holds main(): keep its globals (options, ...) but rename main so the fuzzer's own wins.
objcopy --redefine-sym main=sshd_main_unused sshd.o "$SRC/sshd-nomain.o"
for o in $(make -s -f Makefile -f <(printf 'print-%%:\n\t@echo $($*)\n') print-SSHDOBJS); do
  [ "$o" = sshd.o ] && continue
  [ -f "$o" ] && SSHD_LINK="${SSHD_LINK:-} $o"
done
LIBS_ALL=$(make -s -f Makefile -f <(printf 'print-%%:\n\t@echo $($*)\n') print-SSHDLIBS print-LIBS | tr '\n' ' ')

STANDALONE_MAIN_SRC="${STANDALONE_FUZZ_MAIN:-/opt/mayhem/StandaloneFuzzTargetMain.c}"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_MAIN_SRC" -o "$SRC/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$SRC/lsan_off.o"

build_harness() {
  local name="$1"
  echo ">> building $name"
  $CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS -I. -c "mayhem/harnesses/$name.c" -o "$SRC/$name.o"
  # libFuzzer target
  $CXX $CXXFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -L. -Lopenbsd-compat \
	"$SRC/$name.o" "$SRC/sshd-nomain.o" "$SRC/lsan_off.o" $SSHD_LINK -lssh -lopenbsd-compat $LIBS_ALL \
	-o "$OUT/$name" $LIB_FUZZING_ENGINE
  # standalone reproducer (one input file, runs once)
  $CXX $CXXFLAGS $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -L. -Lopenbsd-compat \
	"$SRC/$name.o" "$SRC/standalone_main.o" "$SRC/sshd-nomain.o" "$SRC/lsan_off.o" $SSHD_LINK -lssh -lopenbsd-compat $LIBS_ALL \
	-o "$OUT/$name-standalone" \
	|| echo "WARNING: standalone build for $name failed (libFuzzer target still produced)" >&2
}

build_harness hostfiles_fuzz

# Functional golden oracle (mayhem/test.sh runs it): built with $SANITIZER_FLAGS because it links the
# sanitized libssh.a.
echo ">> building sshkey_oracle"
$CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -O2 $EXTRA_CFLAGS -I. -L. -Lopenbsd-compat \
	mayhem/harnesses/sshkey_oracle.c -o "$SRC/mayhem-oracle" \
	-lssh -lopenbsd-compat $LIBS_ALL \
  || { echo "ERROR: oracle build failed" >&2; exit 1; }

echo "build.sh complete:"
ls -la "$OUT"/hostfiles_fuzz "$SRC"/mayhem-oracle
