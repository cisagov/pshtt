#!/bin/bash

# If pshtt is done on all machines, it grabs both
# the log file and the output file from the machines and
# places them in the data_results/ directory.

# This script also sets up the files to be combined by
# the combine_shards script. Because pshtt outputs the results
# as a list of dicts, we need to combine all of those lists.
# We output the dicts as a file of dicts, one per line.
hosts_file='hosts.txt'
list_of_files=$(ls -1q input_files)
i=1

for z in $list_of_files; do
  machine=$(sed "${i}q;d" $hosts_file)
  echo 'Kicking off '"${machine}"' number '$i
  # Grab the actual result file.
  echo 'grabbing result file'
  scp -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}":~/pshtt/"${z}".json data_results/
  echo $?
  # Grab the log file from that machine.
  echo 'grabbing log file'
  scp -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}":~/pshtt/time_"${z}".txt data_results/
  echo $?
  echo 'creating to_combine.txt'
  touch data_results/to_combine.txt
  echo $?
  echo 'putting file name into combine script'
  "${z}"'.json' >> data_results/to_combine.txt
  echo $?
  ((i = i + 1))
done

cd data_results || exit
python combine_shards.py to_combine.txt > final_results.json
