"""Define utility functions for the pshtt library."""

# Standard Python Libraries
import contextlib
import csv
import datetime
import errno
import json
import logging
import os
import re
import sys
import traceback


# Display exception without re-throwing it.
def format_last_exception():
    """Pretty format the last raised exception."""
    exc_type, exc_value, exc_traceback = sys.exc_info()
    return "\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback))


# mkdir -p in python, from:
# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    """Make a directory and any missing directories in the path."""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise


def json_for(data):
    """Pretty format the given object to JSON."""
    return json.dumps(data, sort_keys=True, indent=2, default=format_datetime)


def write(content, destination, binary=False):
    """Write contents to a destination after making any missing directories."""
    parent = os.path.dirname(destination)
    if parent != "":
        mkdir_p(parent)

    with open(destination, "bw") if binary else open(
        destination, "w", encoding="utf-8"
    ) as f:
        f.write(content)


def format_datetime(obj):
    """Provide a formatted datetime."""
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    if isinstance(obj, str):
        return obj
    return None


# Load domains from a CSV, skip a header row
def load_domains(domain_csv):
    """Load a list of domains from a CSV file."""
    domains = []
    with open(domain_csv, encoding="utf-8") as csvfile:
        for row in csv.reader(csvfile):
            # Skip empty rows.
            if not row or not row[0].strip():
                continue

            row[0] = row[0].lower()
            # Skip any header row.
            if not domains and row[0].startswith("domain"):
                continue

            domains.append(row[0])
    return domains


# Configure logging level, so logging.debug can hinge on --debug.
def configure_logging(debug_logging=False):
    """Configure the logging library."""
    log_level = logging.DEBUG if debug_logging else logging.WARNING
    logging.basicConfig(format="%(message)s", level=log_level)


def format_domains(domains):
    """Format a given list of domains."""
    formatted_domains = []

    for domain in domains:
        # Replace a single instance of http://, https://, and www. if present.
        formatted_domains.append(re.sub(r"^(https?://)?(www\.)?", "", domain))

    return formatted_domains


def debug(*args, divider=False):
    """Output a debugging message."""
    if divider:
        logging.debug("\n-------------------------\n")

    if args:
        logging.debug(*args)


@contextlib.contextmanager
def smart_open(filename=None):
    """Context manager that can handle writing to a file or stdout.

    Adapted from: https://stackoverflow.com/a/17603000
    """
    handle = sys.stdout if filename is None else open(filename, "w", encoding="utf-8")

    try:
        yield handle
    finally:
        if handle is not sys.stdout:
            handle.close()
