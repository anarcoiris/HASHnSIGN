cmake_minimum_required(VERSION 3.10)
project(hash_gpg_gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ajusta estas rutas según tu layout: asume que ImGui está en extern/imgui con backends.
add_subdirectory(extern/imgui) # si añadiste ImGui como subdir que define imgui target

find_package(SDL2 REQUIRED)
find_package(OpenGL REQUIRED)

include_directories(
    ${SDL2_INCLUDE_DIRS}
    extern/imgui
    extern/imgui/backends
)

add_executable(hash_gpg_gui src/main.cpp)

# Añadir ImGui y backends (si tu subdir crea target "imgui")
target_link_libraries(hash_gpg_gui PRIVATE imgui ${SDL2_LIBRARIES} OpenGL::GL)

# Si usas gl3w/glew, linkéalo también (ejemplo con gl3w)
find_library(GL3W_LIB gl3w)
if (GL3W_LIB)
    target_link_libraries(hash_gpg_gui PRIVATE ${GL3W_LIB})
endif()

# En Windows puede que necesites linkear user32 gdi32 opengl32 etc:
if (WIN32)
    target_link_libraries(hash_gpg_gui PRIVATE opengl32)
endif()
