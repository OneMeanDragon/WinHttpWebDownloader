cmake_minimum_required(VERSION 3.24)
project(WinHttpWebDownloader LANGUAGES CXX)

add_executable(WinHttpWebDownloader
    src/main.cpp
    src/Downloader.cpp
)
target_compile_features(WinHttpWebDownloader PRIVATE cxx_std_23)
target_compile_definitions(WinHttpWebDownloader PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(WinHttpWebDownloader PRIVATE include)
target_link_libraries(WinHttpWebDownloader PRIVATE winhttp bcrypt)
if(MSVC)
    target_compile_options(WinHttpWebDownloader PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()
