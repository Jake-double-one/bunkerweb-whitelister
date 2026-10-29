#!/usr/bin/env sh
# Re-pin requirements.txt (with hashes) to the newest releases on PyPI.
set -eu
cd "$(dirname "$0")/.."
python -m pip install --quiet pip-tools
pip-compile --generate-hashes --strip-extras --upgrade -o requirements.txt requirements.in
