cmake_minimum_required(VERSION 3.2)

project(napi-crypto C)


FILE(GLOB CRYPTO_SOURCE
   src/*.c
   src/*.h
)

add_definitions(-DNAPI_DISABLE_CPP_EXCEPTIONS)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)


add_library(${PROJECT_NAME} SHARED ${CRYPTO_SOURCE})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE ${CMAKE_SOURCE_DIR}/node_modules/node-addon-api
    PRIVATE ${CMAKE_SOURCE_DIR}/node_modules/node-addon-api/src
    PRIVATE ${CMAKE_JS_INC}
)

target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})






