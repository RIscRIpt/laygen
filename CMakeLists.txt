cmake_minimum_required(VERSION 3.15)

project(restruc
    VERSION 0.1
    DESCRIPTION "REstruc: C++ struct recovery tool"
    HOMEPAGE_URL "https://github.com/restruc"
)

find_package(zydis)
find_package(zycore)

file(GLOB SOURCE_FILES
    "src/*.cxx"
    "src/*.hxx"
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

set_target_properties(
    ${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE zycore zydis
)

target_link_directories(
    ${PROJECT_NAME}
    PRIVATE ${zycore_LIB_DIR}
    PRIVATE ${zydis_LIB_DIR}
)

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE ${zycore_INCLUDE_DIR}
    PRIVATE ${zydis_INCLUDE_DIR}
)
