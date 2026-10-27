#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PYTHONPATH="${PROJECT_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
export KDC_KEY_ALICE="${KDC_KEY_ALICE:-alice-master-key}"
export KDC_KEY_BOB="${KDC_KEY_BOB:-bob---master-key}"

cd "${PROJECT_ROOT}"
python -m entities.kdc