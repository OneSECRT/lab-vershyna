cmake_minimum_required(VERSION 3.16)
project(lab3_dstu9212 C)

# DSTU 9212 parameter set: 1, 2, 3 or 4 (cmake -DDSTU9212_MODE=2 ...)
set(DSTU9212_MODE 1 CACHE STRING "DSTU 9212 parameter set (1..4)")
set_property(CACHE DSTU9212_MODE PROPERTY STRINGS 1 2 3 4)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(dstu9212 STATIC
	library/src/api.c
	library/src/convert.c
	library/src/keygen.c
	library/src/ntt_tables.c
	library/src/poly.c
	library/src/reduce.c
	library/src/sign.c
	library/src/tables.c
	library/src/utils.c
	library/third_party/dstu7564/dstu7564.c
	library/third_party/dstu8845/dstu8845.c
)
target_include_directories(dstu9212
	PUBLIC library/include library/third_party
	PRIVATE library/src
)
target_compile_definitions(dstu9212 PUBLIC DSTU9212_MODE=${DSTU9212_MODE})
target_compile_options(dstu9212 PRIVATE -Wall -Wextra -Wpedantic)
if(WIN32)
	# The library takes random bytes from BCryptGenRandom on Windows.
	target_link_libraries(dstu9212 PUBLIC bcrypt)
endif()

add_executable(lab3 student/main.c)
target_link_libraries(lab3 PRIVATE dstu9212)
target_compile_options(lab3 PRIVATE -Wall -Wextra -Wpedantic)

add_executable(demo examples/demo.c)
target_link_libraries(demo PRIVATE dstu9212)
