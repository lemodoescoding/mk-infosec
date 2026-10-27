#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PYTHONPATH="${PROJECT_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
export KDC_KEY_BOB="${KDC_KEY_BOB:-bob---master-key}"
export BOB_HOST="${BOB_HOST:-0.0.0.0}"
export BOB_PORT="${BOB_PORT:-5002}"

cd "${PROJECT_ROOT}"
python3 -m entities.bob
