cmake_minimum_required(VERSION 3.20)
project(jstack_frame_decoder C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(JSTACK_ENABLE_SANITIZERS "Enable address and undefined-behavior sanitizers" OFF)

add_library(frame_decoder STATIC src/frame_decoder.c)
target_include_directories(frame_decoder PUBLIC include)

add_executable(frame_decoder_tests tests/test_frame_decoder.c)
target_link_libraries(frame_decoder_tests PRIVATE frame_decoder)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(frame_decoder PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_compile_options(frame_decoder_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  if(JSTACK_ENABLE_SANITIZERS)
    target_compile_options(frame_decoder PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(frame_decoder_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(frame_decoder_tests PRIVATE -fsanitize=address,undefined)
  endif()
endif()

enable_testing()
add_test(NAME frame_decoder_public COMMAND frame_decoder_tests)
