#!/usr/bin/env python
from string import *
import os, commands, getopt, sys, platform

g_Header = '''/*
 * Copyright 1993-2010 NVIDIA Corporation.  All rights reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property and 
 * proprietary rights in and to this software and related documentation. 
 * Any use, reproduction, disclosure, or distribution of this software 
 * and related documentation without an express license agreement from
 * NVIDIA Corporation is strictly prohibited.
 *
 * Please refer to the applicable NVIDIA end user license agreement (EULA) 
 * associated with this source code for terms and conditions that govern 
 * your use of this NVIDIA software.
 * 
 */

////////////////////////////////////////////////////////////////////////////////
// This file is auto-generated, do not edit
////////////////////////////////////////////////////////////////////////////////
'''


def Usage():
    print "Usage: ptx2c.py in out"
    print "Description: performs embedding in.cubin or in.ptx file into out.c and out.h files as character array" + os.linesep
    sys.exit(0)


def FormatCharHex(d):
    s = hex(ord(d))
    if len(s) == 3:
        s = f"0x0{s[2]}"
    return s


args = sys.argv[1:]
if len(sys.argv[1:]) != 2:
    Usage()

out_h = f"{args[1]}_ptxdump.h"
out_c = f"{args[1]}_ptxdump.c"


with open(args[0], 'r') as h_in:
    source_bytes = h_in.read()
    source_bytes_len = len(source_bytes)

    h_out_c = open(out_c, 'w')
    h_out_c.writelines(g_Header)
    h_out_c.writelines("#include \"" + out_h + "\"\n\n")
    h_out_c.writelines(
        f"unsigned char {args[1]}_ptxdump[{str(source_bytes_len + 1)}"
        + "] = {\n"
    )

    h_out_h = open(out_h, 'w')
    macro_h = f"__{args[1]}_ptxdump_h__"
    h_out_h.writelines(g_Header)
    h_out_h.writelines(f"#ifndef {macro_h}" + "\n")
    h_out_h.writelines(f"#define {macro_h}" + "\n\n")
    h_out_h.writelines('#if defined __cplusplus\nextern "C" {\n#endif\n\n')
    h_out_h.writelines(
        f"extern unsigned char {args[1]}_ptxdump[{str(source_bytes_len + 1)}"
        + "];\n\n"
    )
    h_out_h.writelines("#if defined __cplusplus\n}\n#endif\n\n")
    h_out_h.writelines(f"#endif //{macro_h}" + "\n")

    newlinecnt = 0
    for i in range(0, source_bytes_len):
        h_out_c.write(f"{FormatCharHex(source_bytes[i])}, ")
        newlinecnt += 1
        if newlinecnt == 16:
            newlinecnt = 0
            h_out_c.write("\n")
    h_out_c.write("0x00\n};\n")

h_out_c.close()
h_out_h.close()

print(f"ptx2c: CUmodule {args[0]} packed successfully")
