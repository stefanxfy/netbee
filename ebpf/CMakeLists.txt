# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(netbee-ebpf C)
add_definitions(-Dbpf_target_arm64)