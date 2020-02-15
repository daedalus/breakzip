#!/bin/bash

mkdir -p stage1
build.out/src/mitm_stage1/mitm_stage1 -target ../nullified.zip -output stage1/nullified -shard_size 1000

