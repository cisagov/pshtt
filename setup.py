"""
setup module for pshtt

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
"""

from setuptools import setup

setup(
    name='pshtt',

    # Versions should comply with PEP440
    version='0.1.1',
    description='Scan websites for HTTPS deployment best practices',

    # NCATS "homepage"
    url='https://www.dhs.gov/cyber-incident-response',
    # The project's main homepage
    download_url='https://github.com/dhs-ncats/pshtt',

    # Author details
    author='Department of Homeland Security, National Cybersecurity Assessments and Technical Services team',
    author_email='ncats@hq.dhs.gov',

    license='License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

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

    install_requires=[
        'requests>=2.10.0',
        'sslyze>=0.13.6',
        'wget>=3.2',
        'docopt',
        'requests_cache',
    ],

    # Conveniently allows one to run the CLI tool as `pshtt`
    entry_points={
        'console_scripts': [
            'pshtt = pshtt.cli:main',
        ]
    }
)
