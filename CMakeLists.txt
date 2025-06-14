cmake_minimum_required(VERSION 3.10)

project(ddos_defender C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

add_subdirectory(network)

set(MAIN_SOURCES
    main.c
)

add_executable(ddos_defender ${MAIN_SOURCES})

target_include_directories(ddos_defender PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(ddos_defender PRIVATE network_lib)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

target_include_directories(ddos_defender PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(ddos_defender PRIVATE ${PCAP_LIBRARIES})
target_compile_options(ddos_defender PRIVATE ${PCAP_CFLAGS_OTHER})

target_compile_options(ddos_defender PRIVATE -Wall -Wextra -pedantic)
