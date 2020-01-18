# This code originally published on:
#   https://arcanis.me/en/2015/10/17/cppcheck-and-clang-format
#
# "THE BEER-WARE LICENSE" (Revision 42):
# Evgeniy Alekseev wrote this file. As long as you retain this notice you can
# do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.
# 
# additional target to perform clang-format run, requires clang-format

# get all project files
file(GLOB_RECURSE ALL_SOURCE_FILES *.cpp *.h)

# filter stuff in third-party
set(PROJECT_TRDPARTY_DIR "third-party")
foreach (SOURCE_FILE ${ALL_SOURCE_FILES})
    string(FIND ${SOURCE_FILE} ${PROJECT_TRDPARTY_DIR} PROJECT_TRDPARTY_DIR_FOUND)
    if (NOT ${PROJECT_TRDPARTY_DIR_FOUND} EQUAL -1)
        list(REMOVE_ITEM ALL_SOURCE_FILES ${SOURCE_FILE})
    endif ()
endforeach ()

add_custom_target(clangformat COMMAND /usr/bin/clang-format -style=Google
        -i ${ALL_SOURCE_FILES})
