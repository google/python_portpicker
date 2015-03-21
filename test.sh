#!/bin/sh -ex

echo 'TESTING under Python 2'
mkdir -p build/test_envs/python2
virtualenv --python=python2 build/test_envs/python2
build/test_envs/python2/bin/pip install mock
# Without --upgrade pip won't copy local changes over to a new test install
# unless you've updated the package version number.
build/test_envs/python2/bin/pip install --upgrade .
build/test_envs/python2/bin/python2 src/tests/portpicker_test.py

echo 'TESTING under Python 3'
mkdir -p build/test_envs/python3
virtualenv --python=python3 build/test_envs/python3
build/test_envs/python3/bin/pip install --upgrade .
build/test_envs/python3/bin/python3 src/tests/portpicker_test.py

echo 'TESTING the portserver'
PYTHONPATH=src build/test_envs/python3/bin/python3 src/tests/portserver_test.py

echo PASS
