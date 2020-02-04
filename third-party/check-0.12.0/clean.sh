#!/bin/sh
# Copyright (c) 2019, Pyrofex Corporation.
# Author: Nash E. Foster <leaf@pyrofex.net>

set -e
set -x

PREFIX="${1:-../no_prefix_given}"

aclocal
autoheader
automake -a -f
./configure --prefix=${PREFIX}

make clean distclean
