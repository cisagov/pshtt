#!/usr/bin/env bash

echo "$DOCKER_PW" | docker login -u "$DOCKER_USER" --password-stdin
version=$(./bump_version.sh show)
docker push "$IMAGE_NAME":$version
