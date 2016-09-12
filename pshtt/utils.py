import os
import json
import errno
import csv
import logging
import datetime
import sys
import traceback


# Display exception without re-throwing it.
def format_last_exception():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    return "\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback))


# mkdir -p in python, from:
# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise


def json_for(object):
    return json.dumps(object, sort_keys=True,
                      indent=2, default=format_datetime)


def write(content, destination, binary=False):
    parent = os.path.dirname(destination)
    if parent is not "":
        mkdir_p(parent)

    if binary:
        f = open(destination, 'bw')
    else:
        f = open(destination, 'w')  # no utf-8 in python 2
    f.write(content)
    f.close()


def format_datetime(obj):
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    elif isinstance(obj, str):
        return obj
    else:
        return None


# Load domains from a CSV, skip a header row
def load_domains(domain_csv):
    domains = []
    with open(domain_csv) as csvfile:
        for row in csv.reader(csvfile):
            if (not row[0]) or (row[0].lower().startswith("domain")):
                continue

            row[0] = row[0].lower()

            domains.append(row[0])
    return domains


# Configure logging level, so logging.debug can hinge on --debug.
def configure_logging(debug=False):
    if debug:
        log_level = "debug"
    else:
        log_level = "warn"

    logging.basicConfig(format='%(message)s', level=log_level.upper())
