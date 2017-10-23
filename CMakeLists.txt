cmake_minimum_required(VERSION 3.8)

project(napi-crypto C)

FILE(GLOB CRYPTO_SOURCE
   src/*.c
   src/*.h
)

add_definitions(-DNAPI_DISABLE_CPP_EXCEPTIONS)


message(${CMAKE_JS_LIB})

add_library(${PROJECT_NAME} SHARED ${CRYPTO_SOURCE})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE ${CMAKE_SOURCE_DIR}/node_modules/node-addon-api
    PRIVATE ${CMAKE_SOURCE_DIR}/node_modules/node-addon-api/src
    PRIVATE ${CMAKE_JS_INC}
)

target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})






