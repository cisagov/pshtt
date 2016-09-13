"""
setup module for pshtt

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
"""

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pshtt',

    # Versions should comply with PEP440
    version='0.1.0',

    description='Scan websites for HTTPS deployment best practices',
    long_description=long_description,

    # The project's main homepage
    url='https://github.com/dhs-ncats/pshtt',

    # Author details
    author='18F',

    license='Public Domain',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],

    # What does your project relate to?
    keywords='https best practices',

    packages=['pshtt'],

    # TODO: Loosen dependency restriction as much as possible while avoiding
    # potential incompatibility issues.
    # See https://packaging.python.org/requirements/:
    # "It is not considered best practice to use install_requires to pin
    # dependencies to specific versions, or to specify sub-dependencies (i.e.
    # dependencies of your dependencies). This is overly-restrictive, and
    # prevents the user from gaining the benefit of dependency upgrades."
    install_requires=[
        'requests==2.10.0',
        'SSLyze==0.13.6',
        'wget==3.2',
        'docopt',
        'requests_cache',
    ],

    # Conveniently allows one to run the CLI tool as `pshtt`
    entry_points = {
        'console_scripts': [
            'pshtt = pshtt.cli:main',
        ]
    }
)
