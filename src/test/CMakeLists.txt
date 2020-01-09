set(tests check_simple)
set(cuda_tests check_cuda)

foreach(test ${tests})
    add_executable(${test} ${test}.cpp)
    target_link_libraries(${test} breakzipcore ${LIBS})
    add_test(NAME ${test}_test COMMAND ${test} PROPERTIES TIMEOUT 10)
endforeach()

foreach(cuda_test ${cuda_tests})
    add_executable(${cuda_test} ${cuda_test}.cu)
    target_link_libraries(${cuda_test} breakzipcore ${LIBS})
    add_test(NAME ${cuda_test}_test COMMAND ${cuda_test} PROPERTIES TIMEOUT 10)
endforeach()
