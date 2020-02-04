#!/bin/sh
# Copyright (c) 2019, Pyrofex Corporation.
# Author: Nash E. Foster <leaf@pyrofex.net>

set -e
set -x

PREFIX="${1:-$(readlink -f ../no_prefix_given)}"

autoreconf --install
./configure --prefix=${PREFIX}

make clean distclean
