#!/usr/bin/env bash

version=$(./bump_version.sh show)

git tag v$version && git push --tags
