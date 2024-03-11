include_directories(../3rdpart)
file(GLOB jsoncpp_src_list ../3rdpart/jsoncpp/*.cpp ../3rdpart/jsoncpp/*.h )
add_library(jsoncpp STATIC ${jsoncpp_src_list})
file(GLOB OpenVideoServer_src_list ./*.cpp ./*.h)

add_executable(OpenVideoServer ${OpenVideoServer_src_list})

if(MSVC)
	set_target_properties(OpenVideoServer PROPERTIES COMPILE_FLAGS  ${VS_FALGS} )
else()
	install(TARGETS OpenVideoServer DESTINATION ${INSTALL_PATH_EXECUTABLE})
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	if(EXISTS "/etc/alpine-release")  # 检查是否为 Alpine Linux
		target_link_libraries(OpenVideoServer -Wl,--start-group jsoncpp execinfo ${LINK_LIB_LIST} -Wl,--end-group)
	else ()
		target_link_libraries(OpenVideoServer -Wl,--start-group jsoncpp ${LINK_LIB_LIST} -Wl,--end-group)
	endif()
else ()
	target_link_libraries(OpenVideoServer jsoncpp ${LINK_LIB_LIST})
endif ()
