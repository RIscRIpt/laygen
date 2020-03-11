cmake_minimum_required(VERSION 3.15)

project(restruc
    VERSION 0.1
    DESCRIPTION "REstruc: C++ struct recovery tool"
    HOMEPAGE_URL "https://github.com/restruc"
)

file(GLOB SOURCE_FILES
    "src/*.cxx"
    "src/*.hxx"
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
