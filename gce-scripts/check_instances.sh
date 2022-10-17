#!/bin/bash

# Checks all the instances in hosts and checks the end of the log file
# to see if it's finished. The script prints out FINISHED or NOT FINISHED
# for each host respectively.

hosts_file='hosts.txt'
list_of_files=$(ls -1q input_files)
i=1

# Grab the correct input file for the corresponding machine.
for z in $list_of_files; do
  machine=$(sed "${i}q;d" $hosts_file)
  # Check if the file has 'Wrote Results', which indicates that it's finished.
  ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" tail pshtt/time_"${z}".txt | grep -q 'Wrote results'
  finished=$?
  if [[ "${finished}" -eq 0 ]]; then
    echo 'server '"${machine}"' FINISHED'
  else
    echo 'server '"${machine}"' NOT FINISHED'
  fi
  ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" cat pshtt/time_"${z}".txt | grep -q 'Traceback'
  error=$?
  if [[ "${error}" -eq 0 ]]; then
    echo 'server '"${machine}"' ERROR ON THIS MACHINE. CHECK INSTANCE.'
  else
    echo 'server '"${machine}"' NO ERROR.'
  fi
  ((i = i + 1))
done
