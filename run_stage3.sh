#!/bin/bash -ex


SHARD_FILE=${1:-stage2/shards.00}
CUDA_DEVICE=${2:-0}

echo ${SHARD_FILE}

cat ${SHARD_FILE} | xargs -I % -- /bin/bash -c "build.out/src/gpu_stage3/cuda_stage3 -cuda_device ${CUDA_DEVICE} -input_shard % -target ../nullified.zip -output stage3.out"
