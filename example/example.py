#!/usr/bin/env python

"""example is an example Python library and tool

Usage:
  example [--log-level=LEVEL]
  example (-h | --help)

Options:
  -h --help              Show this message.
  --log-level=LEVEL      If specified, then the log level will be set to
                         the specified value.  Valid values are "debug",
                         "info", "warn", "error", and "critical".
"""

import logging

import docopt


def example():
    """A dummy function."""
    logging.debug("This is a debug message")
    logging.info("This is an info message")
    logging.warn("This is a warning message")
    logging.error("This is an error message")
    logging.critical("This is a critical message")


def main():
    args = docopt.docopt(__doc__, version="0.0.1")

    # Set up logging
    log_level = logging.getLevelName(logging.WARNING)
    if args["--log-level"]:
        log_level = args["--log-level"]
    try:
        logging.basicConfig(
            format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
        )
    except ValueError:
        logging.critical(
            '"{}" is not a valid logging level.  Possible values '
            "are debug, info, warn, and error.".format(log_level)
        )
        return 1

    example()

    # Stop logging and clean up
    logging.shutdown()


if __name__ == "__main__":
    main()
