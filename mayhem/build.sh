#!/usr/bin/env bash
#
# mayhem/build.sh — build axel's fuzz harnesses (sanitized) and its own test
# suite (normal flags). Runs in /mayhem as `mayhem`; re-runnable and offline.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# -Wno-error: upstream enables -Werror with warnings clang 19 trips in test/harness.h.
# Upstream's autotools bootstrap (generated files are gitignored upstream).
autoreconf -if

# 1) Test suite: upstream's `make check` programs, NORMAL flags, out of tree.
mkdir -p mayhem/build-test
( cd mayhem/build-test
  [ -f config.status ] || env -u CFLAGS -u LDFLAGS ../../configure \
      CFLAGS="-O2 -Wno-error $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
  make -j"$MAYHEM_JOBS" axel test/netrc test/conf test/http_params test/tap-run )

# 2) Project with the sanitizers + SanCov, out of tree.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
mkdir -p mayhem/build-fuzz
( cd mayhem/build-fuzz
  [ -f config.status ] || ../../configure CC="$CC" CFLAGS="$FUZZ_CFLAGS -Wno-error"
  make -j"$MAYHEM_JOBS" axel )

B="$SRC/mayhem/build-fuzz"
CPP=(-DHAVE_CONFIG_H -I"$B" -I"$SRC" -I"$SRC/src" -D_BSD_SOURCE -D_DEFAULT_SOURCE
     -DLOCALEDIR='"/usr/local/share/locale"' -pthread)
# Every object of the axel binary except text.c, which holds main(); text.c is
# recompiled with main renamed so its helpers (print_messages, axel_size_human)
# stay available.
OBJS=()
for o in "$B"/src/axel-*.o; do
  [ "$(basename "$o")" = axel-text.o ] || OBJS+=("$o")
done
$CC $FUZZ_CFLAGS "${CPP[@]}" -Dmain=axel_text_main -c "$SRC/src/text.c" -o "$B/fuzz-text.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
OBJS+=("$B/fuzz-text.o" "$B/lsan_off.o")
LIBS=(-lssl -lcrypto -lpthread)

build_harness() { # <name> <source> [extra cflags...]
  local name="$1" src="$2"; shift 2
  $CC $FUZZ_CFLAGS "${CPP[@]}" "$@" -c "$SRC/mayhem/harnesses/$src" -o "$B/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$name.o" "${OBJS[@]}" "${LIBS[@]}" \
      -o "/mayhem/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$name.o" "${OBJS[@]}" "${LIBS[@]}" \
      -o "/mayhem/$name-standalone"
}

build_harness fuzz_http_response fuzz_net.c -DFUZZ_SCHEME='"http"' -DFUZZ_HTTP_RESPONSE
build_harness fuzz_ftp_response  fuzz_net.c -DFUZZ_SCHEME='"ftp"' -DFUZZ_CONN_API
build_harness fuzz_stfile        fuzz_net.c -DFUZZ_SCHEME='"http"' -DFUZZ_STFILE
build_harness fuzz_search        fuzz_net.c -DFUZZ_SCHEME='"http"' -DFUZZ_SEARCH
build_harness fuzz_url           fuzz_url.c
build_harness fuzz_http_params   fuzz_http_params.c
build_harness fuzz_conf          fuzz_conf.c
build_harness fuzz_netrc         fuzz_netrc.c
