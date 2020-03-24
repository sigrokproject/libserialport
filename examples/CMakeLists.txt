
remove_definitions(-DLIBSERIALPORT_ATBUILD)

file(GLOB examples_src "*.c")
foreach(example_path ${examples_src})
    get_filename_component(srcname ${example_path} NAME)
    get_filename_component(execname ${example_path} NAME_WE)

    add_executable(${execname} ${srcname})
    set_target_properties(${execname} PROPERTIES COMPILE_OPTIONS "-Wall")

    target_link_libraries(${execname} ${LIBRARY_NAME})
    target_include_directories(${execname} PUBLIC "${PROJECT_BINARY_DIR}")
endforeach()
