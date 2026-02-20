# Copyright (C) 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.25)

project(gvm-auth-project LANGUAGES C)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

option(BUILD_TESTING "Build tests" ON)

if(BUILD_TESTING)
  message(STATUS "Building tests")

  enable_testing()

  find_package(cgreen REQUIRED)
endif()

add_subdirectory(gvm-auth-c)
