cmake_minimum_required(VERSION 3.10)
project(hash_gpg_gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Si quieres logs más detallados de búsqueda
set(CMAKE_VERBOSE_MAKEFILE ON)

# Ajusta estas rutas según tu layout: asume que ImGui está en extern/imgui con backends.
add_subdirectory(extern/imgui) # si añadiste ImGui como subdir que define target "imgui"

# SDL2 en MSYS2 ya tiene archivo de configuración de CMake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "/mingw64/lib/cmake/SDL2")

find_package(SDL2 REQUIRED)
find_package(OpenGL REQUIRED)

include_directories(
    ${SDL2_INCLUDE_DIRS}
    extern/imgui
    extern/imgui/backends
    /mingw64/include      # asegura rutas correctas en MSYS2
)

add_executable(hash_gpg_gui
    src/main.cpp
)
find_package(SDL2 REQUIRED)
find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED PATHS /mingw64/lib)
# Link básico
target_link_libraries(hash_gpg_gui PRIVATE imgui ${SDL2_LIBRARIES} OpenGL::GL GLEW::GLEW)


# Si usas gl3w (MSYS2: pacman -S mingw-w64-x86_64-gl3w)

if (GLEW)
    target_link_libraries(hash_gpg_gui PRIVATE GLEW::GLEW)
endif()

# En Windows con MinGW necesitas agregar librerías de WinAPI
if (WIN32)
    target_link_libraries(hash_gpg_gui PRIVATE
        opengl32
        gdi32
        user32
        shell32
    )
endif()
