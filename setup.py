"""
This is the setup module for the example project.

Based on:

- https://packaging.python.org/distributing/
- https://github.com/pypa/sampleproject/blob/master/setup.py
- https://blog.ionelmc.ro/2014/05/25/python-packaging/#the-structure
"""

# Standard Python Libraries
from glob import glob
from os.path import basename, splitext

# Third-Party Libraries
from setuptools import find_packages, setup


def readme():
    """Read in and return the contents of the project's README.md file."""
    with open("README.md", encoding="utf-8") as f:
        return f.read()


def package_vars(version_file):
    """Read in and return the variables defined by the version_file."""
    pkg_vars = {}
    with open(version_file) as f:
        exec(f.read(), pkg_vars)  # nosec
    return pkg_vars


setup(
    name="example",
    # Versions should comply with PEP440
    version=package_vars("src/example/_version.py")["__version__"],
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
        "Programming Language :: Python :: 3.8",
    ],
    python_requires=">=3.6",
    # What does your project relate to?
    keywords="skeleton",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={"example": ["data/*.txt"]},
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    include_package_data=True,
    install_requires=["docopt", "setuptools >= 24.2.0", "schema"],
    extras_require={
        "test": [
            "pre-commit",
            # coveralls 1.11.0 added a service number for calls from
            # GitHub Actions. When run this resulted in a 422 response from the
            # coveralls API with the message:
            # Unprocessable Entity for url: https://coveralls.io/api/v1/jobs
            # Temporarily pinning coveralls to before this version until this
            # issue is resolved.
            "coveralls < 1.11.0",
            "coverage",
            "pytest-cov",
            "pytest",
        ]
    },
    # Conveniently allows one to run the CLI tool as `example`
    entry_points={"console_scripts": ["example = example.example:main"]},
)
