#!/bin/sh -ex

python3 -m venv build/venv
. build/venv/bin/activate

pip install --upgrade pip tox twine build
tox -e "py3$(python -c 'import sys; print(sys.version_info.minor)')"
