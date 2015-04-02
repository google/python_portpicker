# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Simple distutils setup for the pure Python portpicker."""

import distutils.core
import sys
import textwrap


def main():
    requires = []
    scripts = []
    py_version = sys.version_info[:2]
    if py_version < (3, 3):
        requires.append('mock(>=1.0)')
    if py_version == (3, 3):
        requires.append('asyncio(>=3.4)')
    if py_version >= (3, 3):
        # The example portserver implementation requires Python 3 and asyncio.
        scripts.append('src/portserver.py')

    distutils.core.setup(
        name='portpicker',
        version='1.1.0',
        description='A library to choose unique available network ports.',
        long_description=textwrap.dedent("""\
          Portpicker provides an API to find and return an available network
          port for an application to bind to.  Ideally suited for use from
          unittests or for test harnesses that launch local servers."""),
        license='Apache 2.0',
        maintainer='Google',
        maintainer_email='greg@krypto.org',
        url='https://github.com/google/python_portpicker',
        package_dir={'': 'src'},
        py_modules=['portpicker'],
        platforms=['POSIX'],
        requires=requires,
        scripts=scripts,
        classifiers=
        ['Development Status :: 5 - Production/Stable',
         'License :: OSI Approved :: Apache Software License',
         'Intended Audience :: Developers', 'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 2.7',
         'Programming Language :: Python :: 3',
         'Programming Language :: Python :: 3.3',
         'Programming Language :: Python :: 3.4',
         'Programming Language :: Python :: Implementation :: CPython',
         'Programming Language :: Python :: Implementation :: Jython',
         'Programming Language :: Python :: Implementation :: PyPy'])


if __name__ == '__main__':
    main()
