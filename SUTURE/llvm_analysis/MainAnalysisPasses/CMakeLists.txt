cmake_minimum_required(VERSION 3.1)
project(SUTURE)
cmake_policy(SET CMP0074 NEW)

find_package(CURL REQUIRED)
find_library(LIBEDIT_LIBRARY NAMES edit REQUIRED)
find_path(LIBEDIT_INCLUDE_DIR NAMES histedit.h REQUIRED)
if(NOT TARGET LibEdit::LibEdit)
  add_library(LibEdit::LibEdit UNKNOWN IMPORTED)
  set_target_properties(LibEdit::LibEdit PROPERTIES IMPORTED_LOCATION "${LIBEDIT_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${LIBEDIT_INCLUDE_DIR}")
endif()

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})

include_directories(${LLVM_INCLUDE_DIRS})

link_directories(${LLVM_LIBRARY_DIRS})

include_directories("z3/include")

link_directories("z3/bin")

add_subdirectory(Utils) # For utilities

add_subdirectory(RangeAnalysis) # For Range Analysis

add_subdirectory(Customizations) # General interface for customizations.

add_subdirectory(LinuxKernelCustomizations) # customizations for linux kernel.

add_subdirectory(SoundyAliasAnalysis) # Smart Alias Analysis

