set(NETWORK_SOURCES
    listener.c
    detector.c
    blocker.c
)

add_library(network_lib STATIC ${NETWORK_SOURCES})

target_include_directories(network_lib PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_options(network_lib PRIVATE -Wall -Wextra -pedantic)
