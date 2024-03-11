CMAKE_POLICY (SET CMP0048 NEW)
project(OpenVideoKit)
cmake_minimum_required(VERSION 3.1.3)
#使能c++11
set(CMAKE_CXX_STANDARD 11)
#加载自定义模块
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

#set(CMAKE_BUILD_TYPE "Release")
if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE "Debug")
endif ()

message(STATUS "编译类型:${CMAKE_BUILD_TYPE}")

#设置bin和lib库目录
set(RELEASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/release)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(LIBRARY_OUTPUT_PATH ${RELEASE_DIR}/linux/${CMAKE_BUILD_TYPE})
    SET(EXECUTABLE_OUTPUT_PATH ${RELEASE_DIR}/linux/${CMAKE_BUILD_TYPE})
    add_compile_options(-fPIC -Wall -Wno-unused-variable -Wno-unused-value)
elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    if (CMAKE_CL_64)
        set(CL_32_64 64)
    else ()
        set(CL_32_64 32)
    endif ()
    SET(LIBRARY_OUTPUT_PATH ${RELEASE_DIR}/windows${CL_32_64}/${CMAKE_BUILD_TYPE})
    SET(EXECUTABLE_OUTPUT_PATH ${RELEASE_DIR}/windows${CL_32_64}/${CMAKE_BUILD_TYPE})
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    SET(LIBRARY_OUTPUT_PATH ${RELEASE_DIR}/mac/${CMAKE_BUILD_TYPE})
    SET(EXECUTABLE_OUTPUT_PATH ${RELEASE_DIR}/mac/${CMAKE_BUILD_TYPE})
    add_compile_options(-Wall -Wno-unused-variable -Wno-unused-value)
endif ()

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

#设置工程源码根目录
set(ToolKit_Root ${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/ZLToolKit/src)
set(MediaKit_Root ${CMAKE_CURRENT_SOURCE_DIR}/src)

#设置头文件目录
INCLUDE_DIRECTORIES(${ToolKit_Root})
INCLUDE_DIRECTORIES(${MediaKit_Root})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/3rdpart)


option(ENABLE_MYSQL "Enable MySQL" true)
option(ENABLE_TESTS "Enable Tests" false)
option(ENABLE_SERVER "Enable Server" true)
option(ENABLE_MEM_DEBUG "Enable Memory Debug" false)
option(ENABLE_ASAN "Enable Address Sanitize" false)
option(ENABLE_PLAYER "Enable Player" true)
option(ENABLE_MSVC_MT "Enable MSVC Mt/Mtd lib" true)
option(ENABLE_CROSS_COMPILE "Enable cross compile" false)

if (MSVC AND ENABLE_MSVC_MT)
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
endif()

# 添加git版本信息
set(COMMIT_HASH "Git_NotFound_Unkown_commit")
set(BRANCH_NAME "Git_NotFound_Unkown_branch")
set(BUILD_TIME "")

string(TIMESTAMP BUILD_TIME "%Y/%m/%d-%H:%M:%S")

find_package(Git QUIET)
if (GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%h
            OUTPUT_VARIABLE COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    execute_process(
            COMMAND ${GIT_EXECUTABLE} symbolic-ref --short -q HEAD
            OUTPUT_VARIABLE BRANCH_NAME
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif ()

configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/version.h.ini
        ${CMAKE_BINARY_DIR}/Version.h
        @ONLY
)

add_definitions(-DENABLE_VERSION)
include_directories(${CMAKE_BINARY_DIR})
message(STATUS "Git version is ${BRANCH_NAME}:${COMMIT_HASH}:${BUILD_TIME}")

if (ENABLE_MEM_DEBUG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-wrap,free  -Wl,-wrap,malloc -Wl,-wrap,realloc -Wl,-wrap,calloc")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wl,-wrap,free  -Wl,-wrap,malloc -Wl,-wrap,realloc -Wl,-wrap,calloc")
    add_definitions(-DENABLE_MEM_DEBUG)
    message(STATUS "已启用内存调试功能")
endif ()

if (ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    message(STATUS "已启用Address Sanitize")
endif ()

set(LINK_LIB_LIST zltoolkit openvideokit)

if (ENABLE_CROSS_COMPILE)
	set(OPENSSL_LIBRARY0 "libssl.a")
	set(OPENSSL_LIBRARY1 "libcrypto.a")
	set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/include")
	set(OPENSSL_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/lib/openssl/${PLATFORM}")
	link_directories(${OPENSSL_LIB_DIR})
	message(STATUS "OPENSSL_INCLUDE_DIR:${OPENSSL_INCLUDE_DIR}")
	add_definitions(-DENABLE_OPENSSL)
	include_directories(${OPENSSL_INCLUDE_DIR})
	list(APPEND LINK_LIB_LIST ${OPENSSL_LIBRARY0})
	list(APPEND LINK_LIB_LIST ${OPENSSL_LIBRARY1})
	list(APPEND LINK_LIB_LIST dl)
else()
endif ()
if (ENABLE_CROSS_COMPILE)
	set(MYSQL_LIBRARIES "libmysqlclient.a")
	set(MYSQL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/include/mysql")
	set(MYSQL_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/lib/mysql/${PLATFORM}")
	link_directories(${MYSQL_LIB_DIR})
	message(STATUS "found library:${MYSQL_LIBRARIES},ENABLE_MYSQL defined")
	message(STATUS "MYSQL_INCLUDE_DIR:${MYSQL_INCLUDE_DIR}")
	add_definitions(-DENABLE_MYSQL)
	include_directories(${MYSQL_INCLUDE_DIR})
	include_directories(${MYSQL_INCLUDE_DIR}/mysql)
	list(APPEND LINK_LIB_LIST ${MYSQL_LIBRARIES})
else()
#查找mysql是否安装
find_package(MYSQL QUIET)
if (MYSQL_FOUND AND ENABLE_MYSQL)
    message(STATUS "found library:${MYSQL_LIBRARIES},ENABLE_MYSQL defined")
    include_directories(${MYSQL_INCLUDE_DIR})
    include_directories(${MYSQL_INCLUDE_DIR}/mysql)
    add_definitions(-DENABLE_MYSQL)
    list(APPEND LINK_LIB_LIST ${MYSQL_LIBRARIES})
else ()
    message(WARNING "mysql，将不支持录像检索")
endif ()
endif()


#set(VS_FALGS "/wd4819 /wd4996 /wd4018 /wd4267 /wd4244 /wd4101 /wd4828 /wd4309 /wd4573 /wd4996" )
set(VS_FALGS "/wd4819")

#收集源代码
file(GLOB ToolKit_src_list ${ToolKit_Root}/*/*.cpp ${ToolKit_Root}/*/*.h ${ToolKit_Root}/*/*.c)
if (IOS)
    list(APPEND ToolKit_src_list ${ToolKit_Root}/Network/Socket_ios.mm)
endif ()

file(GLOB OpenVideoKit_src_list ${MediaKit_Root}/*/*.cpp ${MediaKit_Root}/*/*.h ${MediaKit_Root}/*/*.c)

#去除win32的适配代码
if (NOT WIN32)
    list(REMOVE_ITEM ToolKit_src_list ${ToolKit_Root}/win32/getopt.c)
else ()
    #防止Windows.h包含Winsock.h
    add_definitions(-DWIN32_LEAN_AND_MEAN -DMP4V2_NO_STDINT_DEFS -D_CRT_SECURE_NO_WARNINGS -D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif ()

#添加库
add_library(zltoolkit STATIC ${ToolKit_src_list})
add_library(openvideokit STATIC ${OpenVideoKit_src_list})
list(APPEND  zltoolkit openvideokit)

#安装目录
if (WIN32)
    set(INSTALL_PATH_LIB $ENV{HOME}/${CMAKE_PROJECT_NAME}/lib)
    set(INSTALL_PATH_INCLUDE $ENV{HOME}/${CMAKE_PROJECT_NAME}/include)
else ()
    set(INSTALL_PATH_LIB lib${LIB_SUFFIX})
    set(INSTALL_PATH_INCLUDE include)
    set(INSTALL_PATH_EXECUTABLE bin)
endif ()


if (WIN32)
    list(APPEND LINK_LIB_LIST WS2_32 Iphlpapi shlwapi)
    if (MSVC)
        set_target_properties(zltoolkit PROPERTIES COMPILE_FLAGS ${VS_FALGS})
        set_target_properties(openvideokit PROPERTIES COMPILE_FLAGS ${VS_FALGS})
    endif ()
elseif (NOT ANDROID OR IOS)
    list(APPEND LINK_LIB_LIST pthread)
endif ()

#复制文件过来
execute_process(COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/conf/config.ini ${EXECUTABLE_OUTPUT_PATH}/)


#ios不编译可执行程序
if (IOS)
    return()
endif()

#测试程序
if (ENABLE_TESTS)
    add_subdirectory(tests)
endif ()

#主服务器
if (ENABLE_SERVER)
    add_subdirectory(server)
endif ()

#播放器
if (ENABLE_PLAYER)
    add_subdirectory(player)
endif ()

