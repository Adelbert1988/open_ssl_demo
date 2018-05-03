# Sets the minimum version of CMake required to build your native library.
# This ensures that a certain set of CMake features is available to
# your build.

cmake_minimum_required(VERSION 3.4.1)

# Specifies a library name, specifies whether the library is STATIC or
# SHARED, and provides relative paths to the source code. You can
# define multiple libraries by adding multiple add.library() commands,
# and CMake builds them for you. When you build your app, Gradle
# automatically packages shared libraries with your APK.

#设置编译过程中生成二进制码被剥除，realse比debug减少so大小
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

#C++编译
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

#配置open-ssl加载头文件
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/open-ssl-core/include)

#动态方式加载
add_library(crypto SHARED IMPORTED )
add_library(ssl SHARED IMPORTED )

#引入第三方.so库
set_target_properties(crypto
                      PROPERTIES
                      IMPORTED_LOCATION
                      ${CMAKE_CURRENT_SOURCE_DIR}/open-ssl-core/lib/${ANDROID_ABI}/libcrypto.so)

set_target_properties(ssl
                      PROPERTIES
                      IMPORTED_LOCATION
                      ${CMAKE_CURRENT_SOURCE_DIR}/open-ssl-core/lib/${ANDROID_ABI}/libssl.so)


add_library( # Specifies the name of the library.
             android-encrypt

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/AndroidNativeUtil.cpp
             src/main/cpp/helper/JNIHelper.cpp
             src/main/cpp/helper/EncryptHelper.cpp)

set_target_properties(android-encrypt
                      PROPERTIES
                      #拷贝生成的动态库到指定目录
                      LIBRARY_OUTPUT_DIRECTORY
                      ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI})

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

target_link_libraries( # Specifies the target library. 连接ssl,crypto
                      android-encrypt
                      crypto
                      ssl

                     # Links the target library to the log library
                     # included in the NDK.
                     ${log-lib} )