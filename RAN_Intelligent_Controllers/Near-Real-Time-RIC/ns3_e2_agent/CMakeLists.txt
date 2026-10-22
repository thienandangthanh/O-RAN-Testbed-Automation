# ns3-e2-agent: out-of-process E2 agent for one ns-O-RAN ns-3 E2 node.
# Built inside NIST's e2-interface tree (e2sim/e2sm_examples/ns3_e2_agent),
# against the installed libe2sim (NIST's unmodified generators) and a copy of
# NIST's e2sim/asn1c (E2AP + E2SM-KPM v3), the same shape as kpm_e2sm.
cmake_minimum_required(VERSION 3.14)
project(ns3_e2_agent C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_FLAGS "-g")              # asn1c output is old C; NIST builds it unoptimised
set(CMAKE_CXX_FLAGS "-g -O2 -Wall")

add_subdirectory(asn1c)               # -> asn1_objects

# E2SM-RC v2.0 codec: ric-app-rc's own generated code (RC_E2SM_DIR = rc@a2282ee
# e2sm/, cloned by the Dockerfile) wrapped by rc_codec/rc-codec.c into a shared
# library that exports only rcc_*; its asn1c runtime stays hidden, so it cannot
# clash with NIST's E2AP/KPM asn1c below. Its include path is set alone because
# rc's headers share file names with NIST's (NR-CGI.h, UEID.h, ...).
set(RC_E2SM_DIR "" CACHE PATH "ric-app-rc e2sm directory (lib/ and headers/)")
if(NOT EXISTS "${RC_E2SM_DIR}/lib/E2SM-RC-ControlHeader.c")
  message(FATAL_ERROR "RC_E2SM_DIR must point at ric-app-rc's e2sm directory")
endif()
file(GLOB RC_E2SM_SOURCES "${RC_E2SM_DIR}/lib/*.c")
add_library(rc_codec SHARED rc_codec/rc-codec.c ${RC_E2SM_SOURCES})
set_target_properties(rc_codec PROPERTIES
  C_VISIBILITY_PRESET hidden
  INCLUDE_DIRECTORIES "${RC_E2SM_DIR}/headers;${CMAKE_CURRENT_SOURCE_DIR}/rc_codec"
  COMPILE_OPTIONS "-w")

include_directories(asn1c /usr/local/include/e2sim src)

add_library(ns3_e2_agent_core STATIC
  src/agent-config.cpp
  src/sha256.cpp
  src/metric-map.cpp
  src/asn-util.cpp
  src/kpm-ran-function-description.cpp
  src/kpm-indication-message.cpp
  src/e2ap-builders.cpp
  src/e2ap-inbound.cpp
  src/rc-control.cpp
  src/agent-stats.cpp)
add_dependencies(ns3_e2_agent_core asn1_objects)
target_link_libraries(ns3_e2_agent_core PUBLIC asn1_objects e2sim rc_codec)
target_include_directories(ns3_e2_agent_core PUBLIC rc_codec)

add_executable(ns3-e2-agent
  src/main.cpp
  src/subscription-table.cpp
  src/sctp-association.cpp
  src/ipc-server.cpp
  src/sample-forwarder.cpp
  src/e2-session.cpp)
target_link_libraries(ns3-e2-agent ns3_e2_agent_core)

add_executable(codec-probe tests/codec-probe.cpp tests/codec-probe-e2ap.cpp)
target_link_libraries(codec-probe ns3_e2_agent_core)

add_executable(rc-control-test tests/rc-control-test.cpp)
target_link_libraries(rc-control-test ns3_e2_agent_core)

install(TARGETS ns3-e2-agent codec-probe rc-control-test DESTINATION bin)
install(TARGETS rc_codec DESTINATION lib)
install(FILES tests/fixtures/rc-control-requests.hex DESTINATION share/ns3-e2-agent)
