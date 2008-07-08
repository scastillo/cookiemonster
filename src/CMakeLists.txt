
include_directories(${FLUIDSNARFS_SOURCE_DIR/include})
add_executable(fluidsnarfs fluidsnarfs.c)
target_link_libraries(fluidsnarfs pcap)
message( STATUS ${CMAKE_LIBRARY_PATH} )

#cpack stuff
set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_CONTACT "Sebastian Castillo Builes <castillobuiles@gmail.com>")
include(CPack)