cmake_minimum_required(VERSION 3.8)
project(MIMUW-FORK C)

set(CMAKE_CXX_STANDARD "17")
set(CMAKE_C_STANDARD "11")
set(CMAKE_C_FLAGS "-g -Wall -Wextra -Wno-sign-compare")

add_library(err err.c)
add_library(HashMap HashMap.c)
add_library(Tree Tree.c Node.c)
add_executable(main main.c)
target_link_libraries(main Tree HashMap err pthread)

install(TARGETS DESTINATION .)
