#!/usr/bin/env bash
#
# mayhem/test.sh - run a subset of strace's own test suite against the normal-flags build that
# mayhem/build.sh produced (mayhem/out/test). Each upstream test runs a program from tests/*.c under
# strace and diffs the decoded output with the expected text, so a neutered strace fails them.
# The list is in mayhem/tests.list. Emits a CTRF report.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

. "$SRC/mayhem/tests.list"
T="$SRC/mayhem/out/test/tests"
if [ ! -x "$SRC/mayhem/out/test/src/strace" ] || [ ! -f "$T/Makefile" ]; then
  echo "mayhem/out/test is not built - run mayhem/build.sh first" >&2
  emit_ctrf "automake-tests" 0 1 0
  exit 1
fi
rm -f "${T:?}"/*.log "${T:?}"/*.trs
make -C "$T" -k -j"$MAYHEM_JOBS" check-TESTS TESTS="$TEST_SCRIPTS" >/tmp/strace-tests.out 2>&1 || true
pass=0 fail=0 skip=0
for t in $TEST_SCRIPTS; do
  trs="$T/${t%.test}.trs"
  res=$(sed -n 's/^:test-result: //p' "$trs" 2>/dev/null | head -1)
  case "$res" in
    PASS) pass=$((pass + 1)) ;;
    SKIP) skip=$((skip + 1)); echo "SKIP: $t" ;;
    *) fail=$((fail + 1)); echo "FAIL: $t (${res:-no result})"; tail -20 "$T/${t%.test}.log" 2>/dev/null ;;
  esac
done
emit_ctrf "automake-tests" "$pass" "$fail" "$skip"
