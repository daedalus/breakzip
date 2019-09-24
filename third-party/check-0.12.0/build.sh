#!/bin/bash
#
# Copyright (c) 2017, Pyrofex Corporation.
# Author: Nash E. Foster <leaf@pyrofex.net>
#
# Build third-party libraries.
#
set -e
set -x

PREFIX="${1:-../no_prefix_given}"

aclocal && automake --gnu --add-missing && autoconf
./configure --prefix=${PREFIX}
make all
make install

cp check-config.cmake ${PREFIX}
