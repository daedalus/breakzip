#!/bin/bash -ex

find stage2/ -type f -a -name 'nullified.*' > stage2/all_shards
split -x -n l/4 stage2/all_shards stage2/shards.
