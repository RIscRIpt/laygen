cmake_minimum_required(VERSION 3.15)

project(restruc
    VERSION 0.1
    DESCRIPTION "REstruc: C++ struct recovery tool"
    HOMEPAGE_URL "https://github.com/restruc"
)

find_package(zydis)
find_package(zycore)

set(SOURCE_DIR "src")

file(GLOB_RECURSE SOURCE_FILES
    "${SOURCE_DIR}/*.cxx"
    "${SOURCE_DIR}/*.hxx"
)

file(GLOB DUMMY_SOURCE_FILES
    "test/dummy/*.cxx"
    "test/dummy/*.hxx"
)

set(DUMMY_NAME dummy)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
add_executable(${DUMMY_NAME} ${DUMMY_SOURCE_FILES})

add_dependencies(${PROJECT_NAME} ${DUMMY_NAME})

set_target_properties(
    ${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(
    ${PROJECT_NAME} PRIVATE
    zycore
    zydis
)

target_link_directories(
    ${PROJECT_NAME} PRIVATE
    ${zycore_LIB_DIR}
    ${zydis_LIB_DIR}
)

target_include_directories(
    ${PROJECT_NAME} PRIVATE
    ${SOURCE_DIR}
    ${zycore_INCLUDE_DIR}
    ${zydis_INCLUDE_DIR}
)
