cmake_minimum_required( VERSION 3.16 )
project( Black )

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

include_directories( Include )

set( CMAKE_C_COMPILER   "x86_64-w64-mingw32-g++" )
set( CMAKE_CXX_COMPILER "x86_64-w64-mingw32-g++" )

set( AGENT_SRC_DIR ${CMAKE_SOURCE_DIR}/Source )
set( BIN_DIR ${CMAKE_SOURCE_DIR}/../Bin )
set( OBJ_DIR ${BIN_DIR}/agent_obj )

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -fno-asynchronous-unwind-tables -nostdlib" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-ident -fpack-struct=8 -falign-functions=1" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -ffunction-sections -falign-jumps=1 -w -m64" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-s,--no-seh,--enable-stdcall-fixup" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -masm=intel -fpermissive -mrdrnd" )

set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -fno-asynchronous-unwind-tables -nostdlib" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-ident -fpack-struct=8 -falign-functions=1" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -ffunction-sections -falign-jumps=1 -w -m64" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-s,--no-seh,--enable-stdcall-fixup" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -masm=intel -fpermissive -mrdrnd" )

set( AGENT_BKAPI "" CACHE STRING "Define the agent backend API." )
set( STOMP OFF CACHE BOOL "Enable BK_STOMP." )

if( STOMP )
    add_compile_definitions( INJECTION_STOMPER )
endif()

file( GLOB BLACK_SRC "${AGENT_SRC_DIR}/*.c*" )

file( MAKE_DIRECTORY ${BIN_DIR} )
file( MAKE_DIRECTORY ${OBJ_DIR} )

link_libraries( kernel32 msvcrt )

add_executable(${PROJECT_NAME}.x64.exe 
    ${BLACK_SRC}
)

set_target_properties(${PROJECT_NAME}.x64.exe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
)


