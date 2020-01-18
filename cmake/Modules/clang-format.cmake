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
add_custom_target(clangformat COMMAND /usr/bin/clang-format -style=Google
        -i ${ALL_SOURCE_FILES})
