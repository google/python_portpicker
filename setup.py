"""Simple distutils setup for the pure Python portpicker."""

import sys
import textwrap
import distutils.core


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
      version='1.0.0',
      description='A library to choose unique available network ports.',
      long_description=textwrap.dedent("""
          Portpicker provides an API to find and return an available network
          port for an application to bind to.  Ideally suited for use from
          unittests or for test harnesses that launch a local server."""),
      license='Apache 2.0',
      maintainer='Google',
      url='https://github.com/google/python_portpicker',
      package_dir={'': 'src'},
      py_modules=['portpicker'],
      platforms=['POSIX'],
      requires=requires,
      scripts=scripts,
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: Apache Software License',
          'Intended Audience :: Developers',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: Implementation :: CPython',
          'Programming Language :: Python :: Implementation :: Jython',
          'Programming Language :: Python :: Implementation :: PyPy']
  )


if __name__ == '__main__':
  main()
