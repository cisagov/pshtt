#!/bin/bash

# ./split_up_dataset <input_file> <number_of_shards> <output_file_name>
# Ex: ./split_up_dataset.sh top-1m.nocommas.8.31.2017 100 alexa

# Uses split to break up the input file into N shards.
# Because of how split works, some files will be larger or smaller
# than others, but the sum of the files will equal the length of the
# original file.

# Add .csv suffix because that's what pshtt takes in.

# Place all files into input_files dir for posterity.

input_file=$1
number_of_shards=${2-10}
output_file_name=${3-shard_}

split -a 3 --number=l/"${number_of_shards}" -d "${input_file}" input_files/"${output_file_name}" --additional-suffix=.csv
