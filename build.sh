#!/usr/bin/bash
CLIENT_BUILD_DIR=./build_client
SERVER_BUILD_DIR=./build_server

install -d ${CLIENT_BUILD_DIR}
install -d ${SERVER_BUILD_DIR}

( cd ${CLIENT_BUILD_DIR} && cmake .. && make )
( cd ${SERVER_BUILD_DIR} && cmake ../server && make )
