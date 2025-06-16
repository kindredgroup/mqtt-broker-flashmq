#!/bin/bash
set -e
package_name=$1
tag=$2
if [ -z "$tag" ]; then
   tag="$package_name"
fi
tag_ref=ghcr.io/kindredgroup/mqtt-broker-flashmq/$tag
echo "Building and publishing image with tag: $tag_ref"
docker build -f ../../Dockerfile . --tag $tag_ref --platform linux/amd64
#for ghcr.io access token mentioned in the github secrets and accessed in actions
docker push $tag_ref