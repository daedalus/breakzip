#!/bin/bash
#
# Copyright (c) 2019, Pyrofex Corporation.
# Author: Nash E. Foster <leaf@pyrofex.net>
#
# Clean third-party libraries.
#
set -e
set -x

DEF_PFX="$(readlink -f $(pwd))/build.out"
PREFIX="${1:-${DEF_PFX}}"
SUBDIRS="check-0.12.0"

PREV_DIR=$(readlink -f $(pwd))
for dir in ${SUBDIRS}; do {
	cd ${dir}
	./clean.sh ${PREFIX} || echo "Clean failed for ${dir}";
	cd ..
}; done
