#!/bin/bash

# Installs all the necessary packages for pshtt to run.
# Logs which package it is installing as well as it's success (0) or failure
# (1).
echo 'UPDATE'
apt-get -y update -qq
echo $? ' ERROR CODE'
echo 'PYTHON PIP'
apt-get -y install python-pip -qq
echo $? ' ERROR CODE'
echo 'GIT'
apt-get -y install git -qq
echo $? ' ERROR CODE'
echo 'PYTHON3-PIP'
apt-get -y install python3-pip -qq
echo $? ' ERROR CODE'
echo 'LIBFFI6'
apt-get -y install libffi6 libffi-dev -qq
echo $? ' ERROR CODE'
echo 'LIBSSL'
apt-get -y install build-essential libssl-dev libffi-dev python-dev python3-dev -qq
echo $? ' ERROR CODE'
echo 'SETUPTOOLS'
pip3 install --upgrade setuptools -qq
echo $? ' ERROR CODE'
echo 'CFFI'
pip3 install cffi -qq
echo $? ' ERROR CODE'
echo 'SSLYZE'
pip3 install sslyze -qq
echo $? ' ERROR CODE'
echo 'PUBLIC SUFFIX'
pip3 install publicsuffix -qq
echo $? ' ERROR CODE'
echo 'REQUESTS'
pip3 install --upgrade requests -qq
echo $? ' ERROR CODE'
echo 'DOCOPT'
pip3 install docopt -qq
echo $? ' ERROR CODE'
echo 'PYOPENSSL'
pip3 install pyopenssl -qq
echo $? ' ERROR CODE'
echo 'PYTABLEWRITER'
pip3 install pytablewriter -qq
echo $? ' ERROR CODE'
echo 'TYPING'
pip3 install typing -qq
echo $? ' ERROR CODE'
echo 'FINISHED INSTALLING PACKAGES'
