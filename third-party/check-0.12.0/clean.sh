#!/bin/sh
# Copyright (c) 2019, Pyrofex Corporation.
# Author: Nash E. Foster <leaf@pyrofex.net>

aclocal
automake -a -f
make distclean
