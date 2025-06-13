cmake_minimum_required(VERSION 3.5)
cmake_policy(SET CMP0048 NEW)

project(plugin_libcurl VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_compile_options(-Wall)

# FetchContent is available in CMake 3.11+
include(FetchContent)
FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG v0.7.0 # or the version you want
)
FetchContent_MakeAvailable(jwt-cpp)

add_library(plugin_libcurl SHARED
  pluginstate.h
  curl_functions.h
  authenticatingclient.h

  authenticatingclient.cpp
  curl_functions.cpp
  pluginstate.cpp

  plugin_libcurl.cpp
)

target_link_libraries(plugin_libcurl 
  PUBLIC curl 
  PRIVATE jwt-cpp)

set_target_properties(plugin_libcurl PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(plugin_libcurl PROPERTIES SOVERSION 1)