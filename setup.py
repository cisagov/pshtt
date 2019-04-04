"""
setup module for pshtt

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
"""

from setuptools import setup
from pshtt import __version__


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='pshtt',

    # Versions should comply with PEP440
    version=__version__,
    description='Scan websites for HTTPS deployment best practices',
    long_description=readme(),
    long_description_content_type='text/markdown',

    # NCATS "homepage"
    url='https://www.us-cert.gov/resources/ncats',
    # The project's main homepage
    download_url='https://github.com/cisagov/pshtt',

    # Author details
    author='Cyber and Infrastructure Security Agency',
    author_email='ncats@hq.dhs.gov',

    license='License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ],

    # What does your project relate to?
    keywords='https best practices',

    packages=['pshtt'],

    install_requires=[
        'requests>=2.18.4',
        'sslyze>=2.0.6',
        'wget>=3.2',
        'docopt>=0.6.2',
        'pytablereader>=0.15.0',
        'pytablewriter>=0.27.2',
        'publicsuffix>=1.1.0',
        'pyopenssl>=17.5.0',
        'python-dateutil>=2.7.3',
        'pytz>=2018.5',
    ],

    extras_require={
        'dev': [
            'check-manifest>=0.36',
            'pytest>=3.5.0',
            'semver>=2.7.9',
            'tox>=3.0.0',
            'wheel>=0.31.0'
        ],
    },

    # Conveniently allows one to run the CLI tool as `pshtt`
    entry_points={
        'console_scripts': [
            'pshtt = pshtt.cli:main',
        ]
    }
)
