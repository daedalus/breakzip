GET_FILENAME_COMPONENT(_check_PREFIX "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
set(check_INCLUDE_DIRS ${_check_PREFIX}/include)
set(check_LIBRARY ${_check_PREFIX}/lib/libcheck.a)
