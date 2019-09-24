/* Copyright (c) 2019, Pyrofex Corporation.
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */
#ifndef __BREAKZIP_H__
#define __BREAKZIP_H__

namespace breakzip {

    int main(int argc, char* argv[]);

    bool InitBreakZip(int argc, char* argv[]);

    void ShutdownBreakZip();

}; // namespace

#endif
