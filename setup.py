"""
This is the setup module for the example project.

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
"""

from setuptools import setup


def readme():
    """Read in and return the contents of the project's README.md file."""
    with open("README.md") as f:
        return f.read()


setup(
    name="add",
    # Versions should comply with PEP440
    version="0.0.1",
    description="Example python library",
    long_description=readme(),
    long_description_content_type="text/markdown",
    # NCATS "homepage"
    url="https://www.us-cert.gov/resources/ncats",
    # The project's main homepage
    download_url="https://github.com/cisagov/skeleton-python-library",
    # Author details
    author="Cyber and Infrastructure Security Agency",
    author_email="ncats@hq.dhs.gov",
    license="License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 3 - Alpha",
        # Indicate who your project is intended for
        "Intended Audience :: Developers",
        # Pick your license as you wish (should match "license" above)
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    # What does your project relate to?
    keywords="skeleton",
    packages=["example"],
    install_requires=["docopt"],
    extras_require={"test": ["pre-commit", "pytest"]},
    # Conveniently allows one to run the CLI tool as `example`
    entry_points={"console_scripts": ["example = example.example:main"]},
)
