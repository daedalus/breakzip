#!/usr/bin/env bash
# Removes build directories & files
set -ex

rm -rf build.out
rm -rf build.third-party
(cd third-party && ./clean.sh)

