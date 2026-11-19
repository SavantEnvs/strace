#!/usr/bin/env bash
#
# mayhem/build.sh - build strace for fuzzing, plus a normal build for the functional tests.
#
# strace forks and ptraces its tracee, and ptrace is not available in the Mayhem sandbox, so the
# targets run strace's own main (option parsing) in-process and feed it a simulated tracee:
# mayhem/replay_main.c (syscall decoders) and mayhem/cli_main.c (-e expressions / options). The
# fuzzed code is strace itself, built with AFL++ instrumentation (afl-clang-fast; the Mayhemfiles
# say `afl: true`) and the base's ASan+UBSan flags.
#
# Outputs (all under the gitignored mayhem/out/):
#   /mayhem/mayhem/out/strace-replay    instrumented strace + simulated tracee (syscall decoder targets)
#   /mayhem/mayhem/out/strace-qualify   instrumented strace, -e values read from a file
#   /mayhem/mayhem/out/strace-options   instrumented strace, allow-listed options read from a file
#   /mayhem/mayhem/out/test/            normal-flags strace + a subset of its upstream test suite
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT/afl" "$OUT/test"

# Generated autotools files and xlat headers are gitignored upstream; regenerate them when absent
# (after a `git clean -ffdX`). bootstrap needs no network.
[ -x configure ] || ./bootstrap

# Test names the oracle runs (mayhem/test.sh reads the same list).
. "$SRC/mayhem/tests.list"

# 1) Instrumented strace. mpers (m32/mx32 personalities) is off: it needs multilib compilers.
cd "$OUT/afl"
[ -f config.status ] || "$SRC/configure" --enable-mpers=no --disable-gcc-Werror \
	CC=afl-clang-fast CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS" LDFLAGS="$SANITIZER_FLAGS"
make -j"$MAYHEM_JOBS"
# Three decoders build a constant mask as `<NAME>_HUGE_MASK << <NAME>_HUGE_SHIFT` (0x3f << 26, into
# the sign bit of an int): src/mem.c:75 (mmap flags), src/memfd_create.c:36 (memfd_create flags) and
# src/ipc_shm.c:43 (shmget flags). Both operands are compile-time constants, so the value (0xfc000000)
# never depends on the input; UBSan shift-base would still turn every mmap/memfd_create/shmget record
# into the same non-input-dependent "defect" and stop the fuzzer from getting past it. These three
# objects hold no other signed shift, so rebuild only them without shift-base (shift-exponent and the
# rest of ASan/UBSan stay on). shift-base stays on everywhere else, e.g. src/filter_seccomp.c, whose
# shift amount comes from the input.
rm -f src/libstrace_a-mem.o src/libstrace_a-memfd_create.o src/libstrace_a-ipc_shm.o
make -C src libstrace_a-mem.o libstrace_a-memfd_create.o libstrace_a-ipc_shm.o \
	CFLAGS="-O1 $SANITIZER_FLAGS -fno-sanitize=shift-base $DEBUG_FLAGS"
make -j"$MAYHEM_JOBS" -C src libstrace.a

# lsan_off: leaks aren't the bug class we fuzz for (SPEC 6.2 item 15).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
# Relink strace with the hook (same objects/libraries automake used).
afl-clang-fast -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -o src/strace src/strace-strace.o \
	src/libstrace.a "$OUT/lsan_off.o"

# 2) CLI targets: strace's main renamed to strace_main, driven by mayhem/cli_main.c
#    (strace-qualify: -e expressions; strace-options: allow-listed options).
objcopy --redefine-sym main=strace_main src/strace-strace.o "$OUT/strace-main.o"
for t in qualify options; do
	def=""; [ "$t" = options ] && def="-DCLI_OPTIONS"
	afl-clang-fast -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $def -c "$SRC/mayhem/cli_main.c" -o "$OUT/cli_$t.o"
	afl-clang-fast -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -o "$OUT/strace-$t" "$OUT/cli_$t.o" \
		"$OUT/strace-main.o" src/libstrace.a "$OUT/lsan_off.o"
done

# 3) Syscall-decoder targets (strace-syscall/-netlink/-ioctl/-bpf/-socket/-execve/-dump):
#    mayhem/replay_main.c replays a simulated tracee's syscalls through strace's real option
#    parsing and entry/exit decoding, in-process (ptrace is not available under Mayhem).
#    - strace's init() calls hyperlink_init() once options are parsed and the log is open:
#      redirect that call to the harness's fuzz_replay_hook.
#    - tracee memory reads (process_vm_readv/writev in libstrace.a) go to the harness's fake
#      address space.
objcopy --redefine-sym main=strace_main --redefine-sym hyperlink_init=fuzz_replay_hook \
	src/strace-strace.o "$OUT/strace-main-replay.o"
objcopy --redefine-sym process_vm_readv=fuzz_process_vm_readv \
	--redefine-sym process_vm_writev=fuzz_process_vm_writev src/libstrace.a "$OUT/libstrace-replay.a"
STRACE_INC=$(make -s -C src -f Makefile -f - print-inc <<'MK'
print-inc: ; @echo $(DEFS) $(DEFAULT_INCLUDES) $(strace_CPPFLAGS) $(CPPFLAGS)
MK
)
afl-clang-fast -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $STRACE_INC -I"$OUT/afl/src" \
	-c "$SRC/mayhem/replay_main.c" -o "$OUT/replay_main.o"
afl-clang-fast -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -o "$OUT/strace-replay" "$OUT/replay_main.o" \
	"$OUT/strace-main-replay.o" "$OUT/libstrace-replay.a" "$OUT/lsan_off.o"

# 4) Normal (unsanitized) build of strace and the test programs mayhem/test.sh runs.
cd "$OUT/test"
[ -f config.status ] || env -u CFLAGS -u LDFLAGS "$SRC/configure" --enable-mpers=no \
	--disable-gcc-Werror CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
make -j"$MAYHEM_JOBS"
make -j"$MAYHEM_JOBS" -C tests libtests.a $TEST_PROGRAMS
