#!/usr/bin/env bash

version=$(./bump_version.sh show)

git tag $version && git push --tags
