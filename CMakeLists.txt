cmake_minimum_required(VERSION 3.16)
project(LinusWareQt VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt
find_package(Qt6 COMPONENTS Widgets QUIET)
if(NOT Qt6_FOUND)
    find_package(Qt5 5.15 COMPONENTS Widgets REQUIRED)
    set(QT_VERSION_MAJOR 5)
else()
    set(QT_VERSION_MAJOR 6)
endif()

# Source files
set(SOURCES
    src/ui/LinusWareQt.cpp
)

# Create executable
add_executable(linusware-qt ${SOURCES})

# Link Qt
if(QT_VERSION_MAJOR EQUAL 6)
    target_link_libraries(linusware-qt Qt6::Widgets)
else()
    target_link_libraries(linusware-qt Qt5::Widgets)
endif()

# Install
install(TARGETS linusware-qt DESTINATION bin)
