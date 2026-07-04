cmake_minimum_required(VERSION 3.10)
project(AdBlockerProject VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Hier werden alle deine C++ Dateien zusammengefasst
add_executable(adBlocker 
    adBlocker.cpp 
    adSieve.cpp 
    utils.cpp
)

