cmake_minimum_required (VERSION 2.8)

project(lwip-runner)

set(CMAKE_BUILD_TYPE DEBUG)
set(CMAKE_C_FLAGS "-O0 -ggdb")
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
set(CMAKE_C_FLAGS_RELEASE "-O0 -ggdb")
set(CMAKE_CXX_FLAGS "-O0 -ggdb")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "-O0 -ggdb")

find_path( PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h HINTS "${PCAP_HINTS}/include")

find_library( PCAP_LIBRARY NAMES pcap wpcap HINTS "${PCAP_HINTS}/lib")

find_path(LWIP_DIR src/include/lwip/init.h ${CMAKE_CURRENT_SOURCE_DIR}/../lwip)

find_path(WOLFSENTRY_INCLUDE_DIR wolfsentry/wolfsentry.h)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/lwip-include
	${PCAP_INCLUDE_DIR}
	${LWIP_DIR}/src/include
    ${LWIP_DIR}/contrib/ports/unix/port
	${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${WOLFSENTRY_INCLUDE_DIR}
)

include(${LWIP_DIR}/src/Filelists.cmake)

add_executable(lwip-runner
	${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${LWIP_DIR}/contrib/ports/unix/port/sys_arch.c
	${CMAKE_CURRENT_SOURCE_DIR}/echo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sentry.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ping.c
)
target_link_libraries(lwip-runner ${PCAP_LIBRARY} lwipcore pthread wolfsentry)
