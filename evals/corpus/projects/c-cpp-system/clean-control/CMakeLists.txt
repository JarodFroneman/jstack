cmake_minimum_required(VERSION 3.20)
project(jstack_decimal_counter C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(JSTACK_ENABLE_SANITIZERS "Enable address and undefined-behavior sanitizers" OFF)

add_library(decimal_counter STATIC src/decimal_counter.c)
target_include_directories(decimal_counter PUBLIC include)

add_executable(decimal_counter_tests tests/test_decimal_counter.c)
target_link_libraries(decimal_counter_tests PRIVATE decimal_counter)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(decimal_counter PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_compile_options(decimal_counter_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  if(JSTACK_ENABLE_SANITIZERS)
    target_compile_options(decimal_counter PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(decimal_counter_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(decimal_counter_tests PRIVATE -fsanitize=address,undefined)
  endif()
endif()

enable_testing()
add_test(NAME decimal_counter_public COMMAND decimal_counter_tests)
