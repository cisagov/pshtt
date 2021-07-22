#!/usr/bin/env pytest -vs
"""Tests for example."""

# Standard Python Libraries
import logging
import os
import sys
from unittest.mock import patch

# Third-Party Libraries
import pytest

# cisagov Libraries
import example

div_params = [
    (1, 1, 1),
    (2, 2, 1),
    (0, 1, 0),
    (8, 2, 4),
]

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
)

# define sources of version strings
RELEASE_TAG = os.getenv("RELEASE_TAG")
PROJECT_VERSION = example.__version__


def test_stdout_version(capsys):
    """Verify that version string sent to stdout agrees with the module version."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            example.example.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


def test_running_as_module(capsys):
    """Verify that the __main__.py file loads correctly."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            # F401 is a "Module imported but unused" warning. This import
            # emulates how this project would be run as a module. The only thing
            # being done by __main__ is importing the main entrypoint of the
            # package and running it, so there is nothing to use from this
            # import. As a result, we can safely ignore this warning.
            # cisagov Libraries
            import example.__main__  # noqa: F401
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


@pytest.mark.skipif(
    RELEASE_TAG in [None, ""], reason="this is not a release (RELEASE_TAG not set)"
)
def test_release_version():
    """Verify that release tag version agrees with the module version."""
    assert (
        RELEASE_TAG == f"v{PROJECT_VERSION}"
    ), "RELEASE_TAG does not match the project version"


@pytest.mark.parametrize("level", log_levels)
def test_log_levels(level):
    """Validate commandline log-level arguments."""
    with patch.object(sys, "argv", ["bogus", f"--log-level={level}", "1", "1"]):
        with patch.object(logging.root, "handlers", []):
            assert (
                logging.root.hasHandlers() is False
            ), "root logger should not have handlers yet"
            return_code = None
            try:
                example.example.main()
            except SystemExit as sys_exit:
                return_code = sys_exit.code
            assert return_code is None, "main() should return success"
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert (
                logging.getLevelName(logging.root.getEffectiveLevel()) == level.upper()
            ), f"root logger level should be set to {level.upper()}"
            assert return_code is None, "main() should return success"


def test_bad_log_level():
    """Validate bad log-level argument returns error."""
    with patch.object(sys, "argv", ["bogus", "--log-level=emergency", "1", "1"]):
        return_code = None
        try:
            example.example.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "main() should exit with error"


@pytest.mark.parametrize("dividend, divisor, quotient", div_params)
def test_division(dividend, divisor, quotient):
    """Verify division results."""
    result = example.example_div(dividend, divisor)
    assert result == quotient, "result should equal quotient"


@pytest.mark.slow
def test_slow_division():
    """Example of using a custom marker.

    This test will only be run if --runslow is passed to pytest.
    Look in conftest.py to see how this is implemented.
    """
    # Standard Python Libraries
    import time

    result = example.example_div(256, 16)
    time.sleep(4)
    assert result == 16, "result should equal be 16"


def test_zero_division():
    """Verify that division by zero throws the correct exception."""
    with pytest.raises(ZeroDivisionError):
        example.example_div(1, 0)


def test_zero_divisor_argument():
    """Verify that a divisor of zero is handled as expected."""
    with patch.object(sys, "argv", ["bogus", "1", "0"]):
        return_code = None
        try:
            example.example.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "main() should exit with error"
