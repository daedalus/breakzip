#!/bin/bash
#
# Copyright (c) 2017, Pyrofex Corporation.
# Author: Nash E. Foster <leaf@pyrofex.net>
#
# Build third-party libraries.
#
set -e
set -x

DEF_PFX="$(readlink -f $(pwd))/build.out"
PREFIX="${1:-${DEF_PFX}}"
SUBDIRS="check-0.12.0"

PREV_DIR=$(readlink -f $(pwd))
for dir in ${SUBDIRS}; do {
	cd ${dir}
	./build.sh ${PREFIX} || (echo "Build failed for ${dir}"; exit 1);
	cd ..
}; done
