#!/usr/bin/env bash
# Full verification gate: build and run every suite in three configurations.
# Run inside the container:  ./scripts/dev.sh ./scripts/check.sh
#
# WHY THREE BUILDS:
#   normal   - the code we actually ship and benchmark (-O2)
#   address  - ASan + UBSan: memory safety and undefined behaviour   (SPEC S7, S14)
#   thread   - TSan: data races and lock-order inversions            (SPEC S8, S9)
# ASan and TSan cannot be combined in one binary, which is why this is three
# build trees and not one.
set -euo pipefail

CONFIGS=("${@:-none address thread}")
FAILED=0

for cfg in ${CONFIGS[@]}; do
  dir="build-${cfg}"
  echo ""
  echo "=============================================================="
  echo ">>> configuration: ${cfg}   (${dir})"
  echo "=============================================================="
  cmake -S . -B "${dir}" -G Ninja -DWANREP_SANITIZE="${cfg}" >/dev/null
  cmake --build "${dir}" -j"$(nproc)"
  if ! ctest --test-dir "${dir}" --output-on-failure -j"$(nproc)"; then
    FAILED=1
    echo "!!! configuration ${cfg} FAILED"
  fi
done

echo ""
if [ "${FAILED}" -eq 0 ]; then
  echo "ALL CONFIGURATIONS GREEN"
else
  echo "FAILURES ABOVE"
fi
exit "${FAILED}"
