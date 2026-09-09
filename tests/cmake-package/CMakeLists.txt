# SPDX-License-Identifier: LGPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)
project(libserialport_package_test LANGUAGES C)

find_package(libserialport CONFIG REQUIRED)
add_executable(libserialport_package_test main.c)
target_link_libraries(libserialport_package_test PRIVATE libserialport::libserialport)
