"""example is an example Python library and tool.

Divide one integer by another and log the result. Also log some information
from an environment variable and a package resource.

EXIT STATUS
    This utility exits with one of the following values:
    0   Calculation completed successfully.
    >0  An error occurred.

Usage:
  example [--log-level=LEVEL] <dividend> <divisor>
  example (-h | --help)

Options:
  -h --help              Show this message.
  --log-level=LEVEL      If specified, then the log level will be set to
                         the specified value.  Valid values are "debug", "info",
                         "warning", "error", and "critical". [default: info]
"""

# Standard Python Libraries
import logging
import os
import sys
from typing import Any, Dict

# Third-Party Libraries
import docopt
import pkg_resources
from schema import And, Schema, SchemaError, Use

from ._version import __version__

DEFAULT_ECHO_MESSAGE: str = "Hello World from the example default!"


def example_div(dividend: float, divisor: float) -> float:
    """Print some logging messages."""
    logging.debug("This is a debug message")
    logging.info("This is an info message")
    logging.warning("This is a warning message")
    logging.error("This is an error message")
    logging.critical("This is a critical message")
    return dividend / divisor


def main() -> int:
    """Set up logging and call the example function."""
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)
    # Validate and convert arguments as needed
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            "<dividend>": Use(int, error="<dividend> must be an integer."),
            "<divisor>": And(
                Use(int),
                lambda n: n != 0,
                error="<divisor> must be an integer that is not 0.",
            ),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        return 1

    # Assign validated arguments to variables
    dividend: int = validated_args["<dividend>"]
    divisor: int = validated_args["<divisor>"]
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
    )

    logging.info(f"{dividend} / {divisor} == {example_div(dividend, divisor)}")

    # Access some data from an environment variable
    message: str = os.getenv("ECHO_MESSAGE", DEFAULT_ECHO_MESSAGE)
    logging.info(f'ECHO_MESSAGE="{message}"')

    # Access some data from our package data (see the setup.py)
    secret_message: str = (
        pkg_resources.resource_string("example", "data/secret.txt")
        .decode("utf-8")
        .strip()
    )
    logging.info(f'Secret="{secret_message}"')

    # Stop logging and clean up
    logging.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
