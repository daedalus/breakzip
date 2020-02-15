#!/bin/bash

NUM_CORES=96
SHARD_BEGIN=0
SHARD_END=10030

mkdir -p stage2
touch stage2/start_time
seq ${SHARD_BEGIN} ${SHARD_END} | xargs -t -I % -P ${NUM_CORES} sh -c "mkdir -p stage2/%; build.out/src/mitm_stage2/mitm_stage2 -target ../nullified.zip -input_shard stage1/nullified.% -output stage2/%/nullified >stage2/%/stage2.log 2>&1;"

echo "Processed shards ${SHARD_BEGIN} through ${SHARD_END}"

