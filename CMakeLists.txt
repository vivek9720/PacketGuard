cmake_minimum_required(VERSION 3.12)
project(PacketGuard VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(packetguard
  src/core/diagnostics.cpp
  src/core/byte_view.cpp
  src/core/strings.cpp
  src/core/ip.cpp
  src/core/checksum.cpp
  src/core/time.cpp
  src/core/security_catalog.cpp
  src/packet/packet.cpp
  src/ioc/ioc.cpp
  src/rules/rules.cpp
  src/policy/policy.cpp
)
target_include_directories(packetguard PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(MSVC)
  target_compile_options(packetguard PRIVATE /W4)
else()
  target_compile_options(packetguard PRIVATE -Wall -Wextra -Wpedantic)
endif()

foreach(tool packetscan iocmatch rulecheck policyaudit)
  add_executable(${tool} tools/${tool}.cpp)
  target_link_libraries(${tool} PRIVATE packetguard)
endforeach()

enable_testing()
add_executable(packetguard_tests
  tests/core/core_tests.cpp
  tests/packet/packet_tests.cpp
  tests/ioc/ioc_tests.cpp
  tests/rules/rules_tests.cpp
  tests/policy/policy_tests.cpp
)
target_link_libraries(packetguard_tests PRIVATE packetguard)
add_test(NAME packetguard_tests COMMAND packetguard_tests)
