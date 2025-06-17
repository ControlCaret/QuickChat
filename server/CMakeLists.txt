cmake_minimum_required(VERSION 3.10)

project(QC_server)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++17")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

file(GLOB project_SRCS *.cpp)

include_directories(include)
include_directories(../utils)

add_executable(QC_server ${project_SRCS})

set_property(TARGET QC_server PROPERTY CXX_STANDARD 17)
