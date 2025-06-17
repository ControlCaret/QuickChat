cmake_minimum_required(VERSION 3.10)

project(QuickChat)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++17 -lcurses -lform -pthread -lcrypto -lssl")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/executable)
find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIRS})

find_package(CURL REQUIRED) 
find_package(OpenSSL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

file(GLOB project_SRCS src/*.cpp)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/executable/certificates)
include_directories(include)
include_directories(utils)
add_executable(QuickChat ${project_SRCS})

set(CERTIFICATES_PATH ${CMAKE_CURRENT_SOURCE_DIR}/build_client/executable/certificates/)

add_custom_command(TARGET QuickChat PRE_BUILD COMMAND ${CMAKE_COMMAND} -DCERTIFICATES_PATH=${CERTIFICATES_PATH} -P ${CMAKE_CURRENT_SOURCE_DIR}/SetPath.cmake)

set_property(TARGET QuickChat PROPERTY CXX_STANDARD 17)
target_link_libraries(QuickChat OpenSSL::SSL)
target_link_libraries(QuickChat ${CURSES_LIBRARIES})
