#!/bin/sh
# Builds ucanrun and runs the lab: a real server and runners talking through
# a machine in the middle that records, changes and replays their traffic.
#   sh tests/lab/run.sh          (KEEP=1 leaves the containers running)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
image=${UCANRUN_IMAGE:-ucanrun:lab}
if [ -z "${SKIP_BUILD:-}" ]; then
  docker build -q --target exec -t "$image" "$repo" >/dev/null
fi
mkdir -p "$here/out" "$here/dl"
rm -f "$here/dl/"*
id=$(docker create "$image")
docker cp "$id:/usr/local/bin/ucr" "$here/ucr" >/dev/null
docker rm "$id" >/dev/null
cp "$repo/web/static/app.js" "$here/app.js"
UCANRUN_IMAGE=$image python3 "$here/lab.py"
