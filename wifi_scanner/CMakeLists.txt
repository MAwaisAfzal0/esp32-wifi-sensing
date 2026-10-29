cmake_minimum_required(VERSION 3.5)
add_compile_options(-fdiagnostics-color=always)

# example_connect() from the esp-idf protocol example components handles the
# station connection and the "type ssid and password" prompt over UART0.
set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wifi_scanner)
