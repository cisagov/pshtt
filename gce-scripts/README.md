# Pshtt as an HTTPS status checker #

Welcome! This is the documentation on how to run pshtt to scan sites for their
HTTPS status. These instructions are mostly about how to run it at scale, but at
the end, there are instructions on how to run on a local instance.

This document goes over how to both run pshtt on multiple instances on google
cloud engine and also how to run it as a singular instance on your local
machine. It takes about 30 minutes to set up from start to finish.

Running pshtt on 150 instances takes about 12 - 15 hours for a million sites.
Assume at worst that each site will take 10 seconds (which is the default
timeout) and scale up to whatever timeframe you want to run in based off of
that.

Example: 1000 sites in 2 hours would take 2 instances.

## How to run pshtt on Google Cloud Engine ##

### Before you run ###

1. Set up a [google compute engine
    account](https://cloud.google.com/compute/docs/access/user-accounts/).

1. Make sure you have the correct quota allowances.
    - Go to the [quotas page](https://cloud.google.com/compute/quotas)
      and select the project that you want to run this under.
    - Request quotas --- click on the following items in the list and click
      "edit qutoas" at the top of the page:
      - CPUS (all regions) --> 150
      - In use IP addresses --> 150
      - One Region's in use IPs (ex us-west1) --> 150
      - Same Region's CPUs (ex. us-west1) --> 150

1. Create Instance Group Template.

    You will want to run multiple instances (presumably), and creating an
    Instance Group template allows you to make up to 150 machines under the same
    template.

    - Go to Compute Engine, then click on the Instance templates
      tab and click "Create Instance Template".
    - Name --> "pshtt-template"
    - Machine type -- 1 CPU (n1-standard-1 (1 vCPU, 3.75 GB memory)).
    - Check allow HTTP and HTTPS traffic.
    - Boot Disk --- Ubuntu 14.04 LTS.
    - automatic restart (under management tab) -- off.
    - Hit create.

1. Create a ssh key ONLY for the google cloud instances and upload to your
    profile.

    This is a security measure. ***DO NOT USE YOUR REGULAR SSH KEY.***

    - `cd ~/.ssh && ssh-keygen -t rsa -f gce_pshtt_key`
    - Go to the [metadata
      tab](https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys)
      and hit edit.
    - `cd ~/.ssh && cat gce_pshtt_key.pub`
    - Copy the output of the above command and paste it into the console.

1. Create the instance group.

    It is important to name your instance group something identifiable,
    especially if you are sharing a project with others. Remember this instance
    group name for a later step. ***We recommend that you try one instance at
    first to make sure it works***.

    - Go to the instance group tab.
    - Click Multi-Zone, and select the region that you requested your
      instances for.
    - Chose "pshtt-template" under instance template.
    - Hit create.
    - Welcome to your new instance group!

### Updating data files and setting up to run ###

The following is a set of commands to run to make your running directory.

1. Download the gcloud command line tool.

    - Follow the [download
      link](https://cloud.google.com/sdk/docs/#install_the_latest_cloud_tools_version_cloudsdk_current_version)
      and install the correct sdk for your OS.
    - If this is your first time installing the gcloud command line tool,
      follow the instructions on the page. Do not set any default zones.
    - If you already have this installed, following the following
      instructions:
    - `gcloud init`
      - Click `2` create a new configuration.
      - Enter `pshtt-configuration`
      - Choose the appropriate account
      - Click the appopriate number corresponding to your google project
      - If it complains that the API is not enabled, hit enabled and retry.
      - Do not set default zone or region
      - At this point, your default project should be this google project.
        You can switch to any of your previous projects by running `gcloud
        config set project PROJECTNAME`

1. Setting up your directory.

    - `mkdir ~/pshtt_run`
      - Creates the dir that you will run your program out of.
    - `gcloud compute instances list | sed -n '1!p' | grep
      "<instance-group-name>" | awk '{print $5}' > ~/pshtt_run/hosts.txt`
    - `<instance-group-name>` is what you named the instance group you created
      above.

1. Copy all .sh scripts from this directory:

    - Keep the name of the scripts the same.
    - `chmod +x ~/pshtt_run/*.sh`
      - which will make all the scripts executable.
    - `touch domains.csv`
      - Your domain list, one domain per line, with the input list ending in
        `.csv`.
      - Domains must have the schema stripped of them and no trailing '/',
        such as:
        - `domain.tld`
        - `subdomain.domain.tld`
        - `www.subdomain.domain.tld`
    - `mkdir ~/pshtt_run/data_results/`
    - `mv ~/pshtt_run/combine_shards.py ~/pshtt_run/data_results`
      - Places combine_shards.py into data_results/.
    - `mkdir ~/pshtt_run/input_files/`

1. roots.pem

    We want to use our own CA file when running pshtt. We use the mozilla root
    store for this purpose. Follow instructions on this
    [PR](https://github.com/agl/extract-nss-root-certs).

1. Updating ssh key

    - If your new ssh key is called "gce_pshtt_key", skip this step.
    - If you did not name your ***new*** ssh key gce_pshtt_key, then you will
      need to go through and rename the gce_pshtt_key in all the .sh files to
      whatever you named your key.
    - In vim, this is `:%s/gce_pshtt_key/yourkeynamehere/g <enter>`.

### How to run ###

1. `screen -S pshtt_running`
1. `cd ~/pshtt_run/`
1. `./run_all_scripts <input_file_name> <number_of_shards> <shard_name> >
    log.out`
    - Number of shards == number of hosts
    - Each machine will contain a shard of the data to run.
    - This is the script that sets up all machines and puts all datafiles on
      the machines for running.
    - `./run_all_scripts top-1m.nocommas.8.31.2017 100 alexa`
    - Will produce 100 shards all starting with "alexa" in the input_files
      dir.
      - ex. alexa000.csv
    - NOTE: you can ONLY create 999 shards. If you need more than 999 shards,
      you will need to change the split_up_dataset.sh file.
1. Exit screen `cntr+a+d`

### During the run ###

- `./check_instances.sh`
  - Will print the ip of each host, as well as FINISHED or NOT FINISHED.

### After the run ###

- `./grab_and_combine_data.sh`
  - Will grab all log and result data files, combine data files into one
    large result file, and put these into data_results/.
- Delete your instance group. If you want to run data analysis, jump down to
  the data analysis portion.

## Running pshtt on your local machine ##

1. Copy packages_to_install.sh and install the packages_to_install.sh.
    - `sudo ./packages_to_install.sh`
1. Clone pshtt.
    - `git clone https://github.com/dhs-ncats/pshtt.git`
1. Put roots.pem, running_script.sh, and your input file in the same dir as
    pshtt.
    - Follow directions under Updating data files above on how to get a
      roots.pem.
    - Domains must have the schema stripped of them and no trailing '/', such
      as:
      - `domain.tld`
      - `subdomain.domain.tld`
      - `www.subdomain.domain.tld`
    - `chmod +x running_script.sh` to make it executable.
1. Run `./running_script.sh <input_filename>`
1. Results and profit.
    - Results can be found in `<input_filename>.json`.
    - If you want to be able to use this json file with any of the colab
      notebooks (like the one listed below), you will also need to run
      combine_shards.py.into the same dir as the json file.
      - Copy combine_shards.py into the same dir as the json file.
      - `echo <input_filename>.json > to_combine.txt`
      - `python combine_shards.py to_combine.txt > final_results.json`
    - Log can be found in `time_<input_filename>.txt`.
