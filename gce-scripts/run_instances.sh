#!/bin/bash

# Runs pshtt on all instances, using the correct input file.

hosts_file='hosts.txt'
list_of_files=$(ls -1q input_files/)
i=1

# For each file, find the corresponding machine it's been uploaded to,
# check if the screen exists (create if not) and kick off pshtt on that screen.

for z in $list_of_files; do
  machine=$(sed "${i}q;d" $hosts_file)
  # Check if screen exists.
  echo 'Kicking off '"${machine}"' number '$i
  ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" screen -list | grep -q "pshtt_screen"
  answer=$?
  # If screen does not exist, then create it.
  if [[ "${answer}" -eq 1 ]]; then
    echo 'Creating screen'
    ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" screen -S pshtt_screen -d -m
    echo $?
  fi

  # Run script in screen.
  echo 'Kicking off script'
  ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" "screen -S pshtt_screen -X -p 0 stuff $'cd pshtt && ./running_script.sh $z\n'"
  echo $?
  ((i = i + 1))
done
