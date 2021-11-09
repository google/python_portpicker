#!/bin/sh -ex

unset PYTHONPATH
python3 -m venv build/venv
. build/venv/bin/activate

pip install --upgrade pip
pip install tox
# We should really do this differently, test from a `pip install .` so that
# testing relies on the setup.cfg install_requires instead of listing it here.
pip install psutil
tox -e "py3$(python -c 'import sys; print(sys.version_info.minor)')"
