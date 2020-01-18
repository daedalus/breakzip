#!/bin/bash
#
# Copyright (c) 2017, Pyrofex Corporation.
# Author: Nash E. Foster <leaf@pyrofex.net>

set -ex

#
# Build third-party libraries.
#
TPDIR="third-party"
THIRD_PARTY_BUILD="${1:-build.out}"
DEF_PFX="$(readlink -f $(pwd))/build.out"
BUILD_DIR="${2:-${DEF_PFX}}"
LIBDIR="${THIRD_PARTY_BUILD}/lib"
CMAKE_VARS="-DCMAKE_BUILD_TYPE=${BUILD:-Release}"

#
# The third party libraries currently control their own versions.
#

# This variable controls whether to clone and build the Third-party libraries.
# It can be set to "no" after the first build to skip this step. NEVER check this
# file in with it set to no, or the gitlab-ci will fail. duh!
TPBUILD=${TPBUILD:-"yes"}

if [ "${TPBUILD}" = "yes" ] ; then {
    TPBUILD_ABS=$(readlink -f ${THIRD_PARTY_BUILD})
    ( cd ${TPDIR} && ./build.sh ${TPBUILD_ABS} ) 
} ; fi

SRCDIR=$(readlink -f $(pwd))
if [ ! -d ${BUILD_DIR} ] ; then {
	mkdir -p ${BUILD_DIR};
} ; fi

# Build and Unit test
cd ${BUILD_DIR}
cmake ${CMAKE_VARS} -B${BUILD_DIR} -H${SRCDIR}
make -j 1

# Build the package
cd ${BUILD_DIR}
make package

CTEST_OUTPUT_ON_FAILURE=TRUE make test


