#!/usr/bin/env bash
#
# mayhem/test.sh — run axel's own unit suites (test/netrc, test/conf,
# test/http_params; built by mayhem/build.sh with normal flags) and report CTRF.
# Each suite prints TAP: a "1..N" plan and one "ok"/"not ok" line per asserted
# case. A suite that dies, prints no plan, or comes up short of its plan counts
# as failed, so a neutered (exit 0, no output) program cannot pass.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

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

B="$SRC/mayhem/build-test"
passed=0 failed=0 skipped=0
for suite in netrc conf http_params; do
  bin="$B/test/$suite"
  if [ ! -x "$bin" ]; then
    echo "missing test runner $bin (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)); continue
  fi
  out=$(cd "$B" && "$bin" 2>&1); rc=$?
  printf '%s\n' "$out" | sed "s/^/[$suite] /"
  plan=$(printf '%s\n' "$out" | sed -n 's/^1\.\.\([0-9][0-9]*\).*/\1/p' | head -1)
  ok=$(printf '%s\n' "$out" | grep -E '^ok [0-9]' | grep -vc '# *SKIP' || true)
  sk=$(printf '%s\n' "$out" | grep -E '^ok [0-9].*# *SKIP' -c || true)
  nok=$(printf '%s\n' "$out" | grep -cE '^not ok [0-9]' || true)
  passed=$((passed + ok)); skipped=$((skipped + sk)); failed=$((failed + nok))
  if [ -z "$plan" ]; then
    echo "[$suite] no TAP plan" >&2; failed=$((failed + 1))
  elif [ $((ok + sk + nok)) -lt "$plan" ]; then
    echo "[$suite] ran $((ok + sk + nok)) of $plan planned" >&2
    failed=$((failed + plan - ok - sk - nok))
  fi
  if [ "$rc" -ne 0 ] && [ "$nok" -eq 0 ]; then
    echo "[$suite] exited $rc" >&2; failed=$((failed + 1))
  fi
done

emit_ctrf "axel-tap" "$passed" "$failed" "$skipped"
