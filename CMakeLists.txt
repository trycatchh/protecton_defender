cmake_minimum_required(VERSION 3.10)

project(ddos_defender C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(NFQ REQUIRED libnetfilter_queue)

add_subdirectory(network)

set(MAIN_SOURCES
    main.c
)

add_executable(ddos_defender ${MAIN_SOURCES})

target_include_directories(ddos_defender PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
    ${NFQ_INCLUDE_DIRS}
)

# Link both the network library and pcap/nfq libraries
target_link_libraries(ddos_defender PRIVATE 
    network_lib 
    ${PCAP_LIBRARIES}
    ${NFQ_LIBRARIES}
)

target_compile_options(ddos_defender PRIVATE 
    ${PCAP_CFLAGS_OTHER} 
    -Wall -Wextra -pedantic
)