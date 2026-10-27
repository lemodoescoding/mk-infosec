#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PYTHONPATH="${PROJECT_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
export KDC_KEY_ALICE="${KDC_KEY_ALICE:-alice-master-key}"
# export KDC_HOST="${KDC_HOST:-127.0.0.1}"
# export KDC_PORT="${KDC_PORT:-9000}"
# export BOB_HOST="${BOB_HOST:-127.0.0.1}"
# export BOB_PORT="${BOB_PORT:-9002}"

cd "${PROJECT_ROOT}"
python3 -m entities.alice
