#!/bin/bash

# This file is broken up into three distinct parts.
# The first part is uploading the packages to install
# script to all machines, and kicking it off.
# We do this first because 1) we need those packages to do anything else
# and 2) it takes about 10 - 15 seconds per machine, so we parallelize it.

# The second part is simply a check to see if the packages are finished
# installing. We test the last machine in the list first because if that is
# finished then all the other machines SHOULD also be finished. After we verify
# that the last machine is finished, loop back through all of the machines and
# make sure that they've all finished. If they haven't print out an error
# warning for that machine and stop the whole process.
# Takes the host file and the list of shards and
# scps shards to hosts.
# Also scps various scripts and installs pshtt
# and all the necessary packages.
# List of IPs, separated by line
hosts_file='hosts.txt'
# number of files that we need to cycle through
num_files=$(ls -1q input_files/ | wc -l)
# list of files; we do this deterministically
# because then we can run this command across
# other scripts and expect the same order of files.
list_of_files=$(ls -1q input_files)
# counter to keep track of which machine we're on (for logging purposes).
i=1
# We flip this bit if we find an error with any of the machines. This tells us
# to stop the process so that the user can go by hand and fix the machine.
error_with_packages=1

# Upload script and install packages on all machines.
# parallelized.
################################################################
for x in $list_of_files;
do
    # Grab the ip from hosts.txt that corresponds to the file number we are
    # uploading.
    # If we are uploading file #3 in the list, go to line 3 in the hosts file
    # and upload to that ip.

    machine=$(sed "${i}q;d" $hosts_file)
    echo 'Now on '"${machine}"' number '$i
    # Do not do strict host key checking so that you dont have to type "yes" for
    # each machine.
    echo 'Uploading packages_to_install.sh'
    scp -i ~/.ssh/gce_pshtt_key -o "StrictHostKeyChecking no" packages_to_install.sh ubuntu@"${machine}":~/
    echo $?
    # We echo after each command to ensure that it worked. 0 means success.
    # The Log file is how we can tell if the packages have all been uploaded.
    echo 'Creating packages log file'
    ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" touch package_log_file.txt
    echo $?
    # Check to see if this screen exists already.
    ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" screen -list | grep -q "package_screen"
    answer=$(echo $?)
    # If the screen exists, then we won't create another one. Otherwise, create.
    if [[ "${answer}" -eq 1 ]] ; then
      echo 'Creating screen'
      ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" screen -S package_screen -d -m
      echo $?
    fi
    # Run packages_to_install and pipe to packages_log_file.txt on each machine.
    ssh -i ~/.ssh/gce_pshtt_key -t ubuntu@"${machine}" "screen -S package_screen -X -p 0 stuff $'sudo ./packages_to_install.sh > package_log_file.txt\n'"
    echo $?
    ((i=i+1))
done


# Check that all machines have finished installing packages.
###################################################################
# Grab the last machine in the hosts file. This was the last one to
# be uploaded and kicked off, so presumably it will be the last one
# to finish.
machine=$(sed "${num_files}q;d" $hosts_file)
while true
do
    echo 'Waiting on packages to install'
    # Wait 10 seconds before checking the file again.
    sleep 10
    ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" tail package_log_file.txt | grep -q 'FINISHED INSTALLING PACKAGES'
    finished=$(echo $?)
    if [[ "${finished}" -eq 0 ]]; then
      break
    fi
done

# Since the last machine is finished, go check the other machines.
i=1
for z in $list_of_files;
do
    machine=$(sed "${i}q;d" $hosts_file)
    echo 'Now on '"${machine}"' number '$i
    echo 'Checking packages finished installing'
    ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" tail package_log_file.txt | grep -q 'FINISHED INSTALLING PACKAGES'
    finished=$(echo $?)
    if [[ "${finished}" -eq 0 ]]; then
      # Check if any of the machines had a problem installing packages.
      ssh -i ~/.ssh/gce_pshtt_key ubuntu@"${machine}" cat package_log_file.txt | grep -q '1 ERROR CODE'
      error=$(echo $?)
      if [[ "${error}" -eq 0 ]]; then
        echo 'ERROR WITH '"${machine}"
        error_with_packages=0
      fi
    fi
    ((i=i+1))
done

# If any of the machines had an error with a package, stop the entire process,
# inform the user.
if [[ "${error_with_packages}" -eq 0 ]]; then
    echo 'ERROR FOUND WITH PACKAGES'
    exit 1
fi

# Upload remaining data files.
#####################################################################
i=1
for y in $list_of_files;
do
    machine=$(sed "${i}q;d" $hosts_file)
    echo 'Now on '"${machine}"' number '$i
    echo 'Cloning github repo file'
    ssh -i ~/.ssh/gce_pshtt_key -t ubuntu@"${machine}" git clone https://github.com/dhs-ncats/pshtt.git
    echo $?
    echo 'copying data file to pshtt directory'
    scp -i ~/.ssh/gce_pshtt_key input_files/"${y}" ubuntu@"${machine}":~/pshtt/
    echo $?
    echo 'Copying roots.pem into pshtt directory'
    scp -i ~/.ssh/gce_pshtt_key "roots.pem" ubuntu@"${machine}":~/pshtt/
    echo $?
    echo 'Copying running script into pshtt directory'
    scp -i ~/.ssh/gce_pshtt_key running_script.sh ubuntu@"${machine}":~/pshtt/
    echo $?
    echo "${y}";
    ((i=i+1))
done

