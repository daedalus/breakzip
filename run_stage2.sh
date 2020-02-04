#!/bin/bash

# build.out/src/mitm_stage1/mitm_stage1 -target ../nullified.zip -output stage1/nullified

NUM_CORES=90
SHARD_BEGIN=0
SHARD_END=1000

seq ${SHARD_BEGIN} ${SHARD_END} | xargs -I % mkdir -p stage2/% ; 
seq ${SHARD_BEGIN} ${SHARD_END} | xargs -I % -P ${NUM_CORES} \
    build.out/src/mitm_stage2/mitm_stage2 \
        -target ../nullified.zip \
        -input_shard stage1/nullified.% \
        -output stage2/%/nullified \
        >>stage2/${i}/stage2.log 2>&1 ;

echo "Processed shards ${SHARD_BEGIN} through ${SHARD_END}"

