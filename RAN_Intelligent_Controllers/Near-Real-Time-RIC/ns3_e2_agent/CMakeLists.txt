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

include_directories(asn1c /usr/local/include/e2sim src)

add_library(ns3_e2_agent_core STATIC
  src/agent-config.cpp
  src/sha256.cpp
  src/metric-map.cpp
  src/asn-util.cpp
  src/kpm-ran-function-description.cpp
  src/kpm-indication-message.cpp
  src/e2ap-builders.cpp
  src/e2ap-inbound.cpp)
add_dependencies(ns3_e2_agent_core asn1_objects)
target_link_libraries(ns3_e2_agent_core PUBLIC asn1_objects e2sim)

add_executable(ns3-e2-agent
  src/main.cpp
  src/agent-stats.cpp
  src/subscription-table.cpp
  src/sctp-association.cpp
  src/ipc-server.cpp
  src/sample-forwarder.cpp
  src/e2-session.cpp)
target_link_libraries(ns3-e2-agent ns3_e2_agent_core)

add_executable(codec-probe tests/codec-probe.cpp tests/codec-probe-e2ap.cpp)
target_link_libraries(codec-probe ns3_e2_agent_core)

install(TARGETS ns3-e2-agent codec-probe DESTINATION bin)
