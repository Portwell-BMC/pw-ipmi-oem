cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

cmake_policy (SET CMP0054 NEW)

option (YOCTO "Use YOCTO depedencies system" OFF)
include (ExternalProject)
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

option (USING_ENTITY_MANAGER_DECORATORS
        "Enable using EM decorators to map FRUs to entity IDs" OFF)

set (
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -Werror \
    -Wtype-limits \
    -Wnull-dereference \
"
)

project (pw-ipmi-oem CXX)

add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)
add_definitions (-DBOOST_ASIO_DISABLE_THREADS)
add_definitions (-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
add_definitions (-Wno-psabi)

if (NOT DEFINED SEL_LOG_DIR OR "${SEL_LOG_DIR}" STREQUAL "")
    set (SEL_LOG_DIR "/var/log" STRING)
    message (WARNING "SEL_LOG_DIR is undefined. Set default value ${SEL_LOG_DIR}.")
endif()
add_definitions(-DSEL_LOG_DIR="${SEL_LOG_DIR}")

if (YOCTO)
    find_package (PkgConfig REQUIRED)
    pkg_check_modules (LOGGING phosphor-logging REQUIRED)
    include_directories (SYSTEM ${LOGGING_INCLUDE_DIRS})
    link_directories (${LOGGING_LIBRARY_DIRS})

    pkg_check_modules (LIBIPMID libipmid REQUIRED)
    include_directories (SYSTEM ${LIBIPMID_INCLUDE_DIRS})
    link_directories (${LIBIPMID_LIBRARY_DIRS})
endif ()

if (NOT USING_ENTITY_MANAGER_DECORATORS)
    execute_process(COMMAND ls ${SENSOR_YAML_GEN} RESULT_VARIABLE result OUTPUT_QUIET ERROR_QUIET)
    if (result)
        message(FATAL_ERROR "SENSOR_YAML_GEN(${SENSOR_YAML_GEN}) is not valid")
    endif ()
endif ()

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

include_directories (SYSTEM ${CMAKE_BINARY_DIR})

if (USING_ENTITY_MANAGER_DECORATORS)
add_library (zpwoemcmds
             SHARED src/storagecommands.cpp src/appcommands.cpp
             src/ipmi_to_redfish_hooks.cpp)
else ()
add_custom_command(OUTPUT sensor-gen.cpp
                  COMMAND python3 ./scripts/sensor_gen.py -i ${SENSOR_YAML_GEN}
                                                          -o ${CMAKE_BINARY_DIR}/ generate-cpp
                  MAIN_DEPENDENCY ${SENSOR_YAML_GEN}
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(run ALL DEPENDS sensor-gen.cpp)

add_library (zpwoemcmds
             SHARED src/storagecommands.cpp src/appcommands.cpp
             src/ipmi_to_redfish_hooks.cpp
             sensor-gen.cpp)
endif ()
set_target_properties (zpwoemcmds PROPERTIES VERSION "0.1.0")
set_target_properties (zpwoemcmds PROPERTIES SOVERSION "0")
target_link_libraries (zpwoemcmds stdc++fs)
target_link_libraries (zpwoemcmds ipmid)
target_link_libraries (zpwoemcmds sdbusplus)
target_link_libraries (zpwoemcmds phosphor_logging)
target_link_libraries (zpwoemcmds -luserlayer)
target_link_libraries (zpwoemcmds -lchannellayer)

install (TARGETS zpwoemcmds DESTINATION lib/ipmid-providers)

target_compile_definitions (
    zpwoemcmds PRIVATE
    $<$<BOOL:${USING_ENTITY_MANAGER_DECORATORS}>:
    -DUSING_ENTITY_MANAGER_DECORATORS>
)
