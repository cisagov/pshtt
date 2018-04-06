#!/usr/bin/env bash

version=$(./bump_version.sh show)
docker build -t ${IMAGE_NAME}:$version .
