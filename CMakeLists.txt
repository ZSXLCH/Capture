cmake_minimum_required(VERSION 3.16)

project(WireWhale VERSION 0.1 LANGUAGES CXX)

# Qt基础配置
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
)

# 可执行文件配置
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(WireWhale
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    add_executable(WireWhale ${PROJECT_SOURCES})
endif()

# === WinPcap 配置 ===
# 设置WinPcap路径（根据实际情况修改）
set(WINPCAP_DIR "D:/WpdPack")
set(WINPCAP_ARCH "x64")  # 或 "x86"，根据你的平台选择
set(WINPCAP_INCLUDE_DIR "${WINPCAP_DIR}/Include")
set(WINPCAP_LIB_DIR "${WINPCAP_DIR}/Lib/${WINPCAP_ARCH}")

# 包含头文件目录
include_directories(${WINPCAP_INCLUDE_DIR})

# 查找WinPcap库（使用变量避免硬编码路径）
find_library(WPCAP_LIB NAMES wpcap PATHS ${WINPCAP_LIB_DIR})
find_library(PACKET_LIB NAMES packet PATHS ${WINPCAP_LIB_DIR})

# 打印库路径用于调试
message(STATUS "WinPcap库路径: ${WPCAP_LIB}")
message(STATUS "Packet库路径: ${PACKET_LIB}")

# 链接库（关键：调整链接顺序，将WinPcap库放在Qt库之前）
target_link_libraries(WireWhale PRIVATE
    ${WPCAP_LIB}       # WinPcap核心库
    ${PACKET_LIB}      # 数据包处理库
    ws2_32             # Windows套接字库
    iphlpapi           # IP helper库
    Qt${QT_VERSION_MAJOR}::Widgets  # Qt库放在最后
)

# 其他配置（保持不变）
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.WireWhale)
endif()
set_target_properties(WireWhale PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS WireWhale
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(WireWhale)
endif()
