#!/bin/bash

# This is the first script to run. This script calls
# all the other pertinent scripts for setting up
# and kicking off runs.

# ./run_all_scripts.sh <data_file_to_split> <#_of_shards> <shard_output_prepend>
# Ex: ./run_all_scripts.sh top-1m.nocommas.8.31.2017 100 alexa

# Only the first input argument is required. The other two will default
# to 10 and shard respectively.

# will split up the file top-1m.nocommas.8.31.2017 into 100 files
# into a dir called input_files, and all the files will start with
# alexa_. So the shard files will be alexa000.csv, alexa001.csv
# etc.

# If any of the scripts fails, this hard fails and tells the user what script
# went wrong.

input_file=$1
number_of_shards=${2-10}
output_file_name=${3-shard_}

echo 'Splitting dataset'
./split_up_dataset.sh "${input_file}" "${number_of_shards}" "${output_file_name}"
error=$?

if [[ "${error}" -eq 1 ]]; then
  echo 'ERROR WITH SPLIT DATASET SCRIPT'
  exit 1
fi

echo 'Scp and setup'
./scp_and_setup.sh "${output_file_name}"
error=$?
if [[ "${error}" -eq 1 ]]; then
  echo 'ERROR WITH SCP AND SETUP SCRIPT'
  exit 1
fi

echo 'Running instances'
./run_instances.sh
error=$?
if [[ "${error}" -eq 1 ]]; then
  echo 'ERROR WITH RUNNING INSTANCES SCRIPT'
  exit 1
fi
