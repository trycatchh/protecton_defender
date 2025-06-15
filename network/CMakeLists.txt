set(NETWORK_SOURCES
    listener.c
    detector.c
    blocker.c
)

add_library(network_lib STATIC ${NETWORK_SOURCES})

target_include_directories(network_lib PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
    ${NFQ_INCLUDE_DIRS}
)

# Link pcap to the network library
target_link_libraries(network_lib PRIVATE 
    ${PCAP_LIBRARIES}
    ${NFQ_LIBRARIES}
)

target_compile_options(network_lib PRIVATE 
    ${PCAP_CFLAGS_OTHER} 
    -Wall -Wextra -pedantic
)