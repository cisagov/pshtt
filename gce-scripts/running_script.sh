#!/bin/bash

# Runs pshtt with a 10 second time, "Google-Transparency-Report" as the user
# agent, with roots.pem as the CA file, and debug on. Logging goes to
# time_<input_file_name>.txt

# ./running_script.sh test_file.csv
# output files: test_file.csv.json, time_test_file.csv.txt

input_file=$1
(time python3 -m pshtt.cli "${input_file}" -t 10 -u -j -o "${input_file}".json -f "roots.pem" --debug) 2> time_"${input_file}".txt
