#!/usr/bin/env pytest -vs
"""Tests for example."""

import pytest

from example import example_div

div_params = [
    (1, 1, 1),
    (2, 2, 1),
    (0, 1, 0),
    (8, 2, 4),
    pytest.param(0, 0, 0, marks=pytest.mark.xfail(raises=ZeroDivisionError)),
]


@pytest.mark.parametrize("dividend, divisor, quotient", div_params)
def test_division(dividend, divisor, quotient):
    """Verify division results."""
    result = example_div(dividend, divisor)
    assert result == quotient, "result should equal quotient"  # nosec


def test_zero_division():
    """Verify that division by zero throws the correct exception."""
    with pytest.raises(ZeroDivisionError):
        example_div(1, 0)
