/*
 * Copyright (c) 2019, Pyrofex Corporation.
 * Author: Nash E. Foster <leaf@pyrofex.net>
 */
#include "breakzip.h"
#include "breakzip_config.h"

#include <sstream>
#include <string>
#include <iostream>

#include <gflags/gflags.h>

const char * usage_message = R"usage(
    -flagfile                   load flags from file     type: string default: ""
    -fromenv                    set flags from the environment [use 'export FLAGS_flag1=value']
                                type: string default: ""
    -tryfromenv                 set flags from the environment if present.
                                type: string default: ""
    -undefok                    comma-separated list of flag names that it is okay to
                                specify on the command line even if the program does not
                                define a flag with that name.  IMPORTANT: flags in this
                                list that have arguments MUST use the flag=value format.
                                type: string default: ""

    -tab_completion_columns     Number of columns to use in output for tab completion
                                type: int32 default: 80
    -tab_completion_word        If non-empty, HandleCommandLineCompletions() will hijack
                                the process and attempt to do bash-style command line flag
                                completion on this value. type: string default: ""

    -help                       Show help on all flags [tip: all flags can have two dashes]
                                type: bool default: false
    -helpfull                   Show help on all flags -- same as -help.
                                type: bool default: false
    -helpmatch                  show help on modules whose name contains the specified substr
                                type: string default: ""
    -helpon                     Show help on the modules named by this flag value.
                                type: string default: ""
    -helppackage                Show help on all modules in the main package.
                                type: bool default: false
    -helpshort                  Show help on only the main module for this program.
                                type: bool default: false
    -helpxml                    Produce an xml version of help. type: bool default: false
    -version                    Show version and build info and exit. type: bool default: false

    -debug                      Enable debugging output. type: bool default: false
    -log_level                  Set the log level. type: int32 default: 3
    )usage";


namespace breakzip {
    using namespace std;

    static std::string version_string() {
        ostringstream ss;
        ss << BREAKZIP_VERSION_MAJOR << "." << BREAKZIP_VERSION_MINOR <<
            "." << BREAKZIP_VERSION_PATCH << " (c) Pyrofex Corporation. ";
        return move(ss.str());
    }

    int main(int argc, char* argv[]) {
        auto initok = InitBreakZip(argc, argv);
        if (!initok) {
            fprintf(stderr, "Intiailization failed!\n");
            exit(-1);
        }

        int exit_code = 0;

        ShutdownBreakZip();
        return exit_code;
    }


    bool InitBreakZip(int argc, char* argv[]) {
        int my_argc = argc;

        google::SetVersionString(version_string());
        google::SetUsageMessage(usage_message);
        auto non_flag = google::ParseCommandLineFlags(&my_argc, &argv, false);

        /* NB(leaf): for now we throw away all non-flag arguments */
        return true;
    }

    void ShutdownBreakZip() {
        return;
    }
}; // namespace

