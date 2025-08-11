// src/main.cpp
// Prototipo: Dear ImGui GUI para generar/firma y verificar hashes.md5 + hashes.md5.asc
// Requisitos: C++17, SDL2, OpenGL3, Dear ImGui backends.
// Compilar con CMake (ver CMakeLists.txt abajo).

#include <imgui.h>
#include "imgui_impl_sdl.h"
#include "imgui_impl_opengl3.h"

#include <SDL.h>
#include <SDL_opengl.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <memory>
#include <array>

namespace fs = std::filesystem;

// Ejecuta un comando y captura stdout+stderr (retorna pair: exit_code, output)
static std::pair<int,std::string> run_command_capture(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;

#ifdef _WIN32
    // On Windows, use "bash -lc" if user wants to run in Git Bash environment:
    // But here we call popen directly; user must ensure md5sum/gpg are in PATH for the process.
    FILE* pipe = _popen((cmd + " 2>&1").c_str(), "r");
#else
    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
#endif
    if (!pipe) return { -1, "popen failed" };
    while (fgets(buffer.data(), (int)buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
#ifdef _WIN32
    int rc = _pclose(pipe);
#else
    int rc = pclose(pipe);
#endif
    return { rc, result };
}

// Escribe hashes.md5 dentro de 'repo' recorriendo ficheros y usando md5sum por archivo
static bool generate_hashes_md5(const fs::path& repo, std::string& out_log) {
    fs::path hashes_path = repo / "hashes.md5";
    std::ofstream ofs(hashes_path, std::ios::trunc);
    if (!ofs.is_open()) {
        out_log += "Error: no se puede crear " + hashes_path.string() + "\n";
        return false;
    }

    // Recorre archivos recursivamente, excluyendo .git y los hashes previos
    for (auto& p : fs::recursive_directory_iterator(repo)) {
        if (!p.is_regular_file()) continue;
        auto rel = fs::relative(p.path(), repo);
        std::string srel = rel.string();
        if (srel.rfind(".git", 0) == 0) continue; // empieza por .git
        if (srel == "hashes.md5" || srel == "hashes.md5.asc") continue;

        // Ejecuta md5sum sobre el archivo y captura la línea
        std::string cmd = "md5sum \"" + p.path().string() + "\"";
        auto [rc, out] = run_command_capture(cmd);
        if (rc != 0) {
            out_log += "md5sum fallo para " + p.path().string() + " :\n" + out + "\n";
            ofs.close();
            return false;
        }
        // md5sum devuelve: "<hash>  /full/path/to/file\n"
        // Queremos dejar las rutas relativas dentro del repo para verificación con md5sum -c
        // Así que reemplazamos la ruta absoluta por ./<relpath>
        // Tomamos la primera token (hash) y la segunda (path) separadas por espacios
        std::istringstream iss(out);
        std::string hash, path_out;
        if (!(iss >> hash)) continue;
        // Rest of line is path (may include spaces). Get remainder of out after hash.
        auto pos = out.find(hash);
        std::string remainder = out.substr(pos + hash.size());
        // Trim leading whitespace
        size_t start = remainder.find_first_not_of(" \t");
        std::string fullpath = (start==std::string::npos) ? "" : remainder.substr(start);
        // remove trailing newline
        while(!fullpath.empty() && (fullpath.back() == '\n' || fullpath.back() == '\r')) fullpath.pop_back();

        // Use relative path prefixed with ./
        std::string relpath = "./" + srel;
        ofs << hash << "  " << relpath << "\n";
    }
    ofs.close();
    out_log += "Generado: " + hashes_path.string() + "\n";
    return true;
}

// Firma hashes.md5 con gpg y opcional default key
static bool sign_hashes(const fs::path& repo, const std::string& gpg_key, std::string& out_log) {
    fs::path hashes = repo / "hashes.md5";
    fs::path asc = repo / "hashes.md5.asc";
    if (!fs::exists(hashes)) {
        out_log += "No existe " + hashes.string() + "\n";
        return false;
    }
    std::string cmd;
    if (!gpg_key.empty()) {
        cmd = "gpg --default-key " + gpg_key + " --armor --output \"" + asc.string() + "\" --sign \"" + hashes.string() + "\"";
    } else {
        cmd = "gpg --armor --output \"" + asc.string() + "\" --sign \"" + hashes.string() + "\"";
    }
    auto [rc, out] = run_command_capture(cmd);
    out_log += out;
    if (rc != 0) {
        out_log += "gpg sign failed (rc=" + std::to_string(rc) + ")\n";
        return false;
    }
    out_log += "Firmado: " + asc.string() + "\n";
    return true;
}

// Git add/commit/push
static bool git_add_commit_push(const fs::path& repo, std::string& out_log) {
    auto run = [&](const std::string& c)->bool {
        auto [rc,out] = run_command_capture("cd \"" + repo.string() + "\" && " + c);
        out_log += out;
        if (rc != 0) {
            out_log += "Comando git fallo: " + c + "\n";
            return false;
        }
        return true;
    };

    if (!run("git add hashes.md5 hashes.md5.asc")) return false;
    // Check if there is something to commit
    auto [rcStatus, statusOut] = run_command_capture("cd \"" + repo.string() + "\" && git status --porcelain");
    if (rcStatus != 0) {
        out_log += statusOut;
        return false;
    }
    if (statusOut.empty()) {
        out_log += "No hay cambios para commitear en " + repo.string() + "\n";
        return true; // no error
    }
    if (!run("git commit -m \"añadiendo fichero de hashes firmado\"")) return false;
    if (!run("git push")) return false;
    out_log += "Push OK para " + repo.string() + "\n";
    return true;
}

static bool verify_signature(const fs::path& repo, const std::string& gpg_key, std::string& out_log) {
    fs::path asc = repo / "hashes.md5.asc";
    fs::path hashes = repo / "hashes.md5";
    if (!fs::exists(asc) || !fs::exists(hashes)) {
        out_log += "Faltan archivos de firma o hashes en " + repo.string() + "\n";
        return false;
    }
    std::string cmd;
    if (!gpg_key.empty()) {
        cmd = "gpg --verify --keyid-format LONG \"" + asc.string() + "\" \"" + hashes.string() + "\"";
    } else {
        cmd = "gpg --verify \"" + asc.string() + "\" \"" + hashes.string() + "\"";
    }
    auto [rc, out] = run_command_capture(cmd);
    out_log += out;
    if (rc != 0) {
        out_log += "gpg verify returned rc=" + std::to_string(rc) + "\n";
        // still return false in case of problem
        return false;
    }
    bool good = (out.find("Good signature") != std::string::npos);
    if (good) out_log += "Firma válida en " + repo.string() + "\n";
    else out_log += "Firma NO válida o no verificable en " + repo.string() + "\n";
    return good;
}

static bool verify_md5sum(const fs::path& repo, std::string& out_log) {
    fs::path hashes = repo / "hashes.md5";
    if (!fs::exists(hashes)) {
        out_log += "No existe " + hashes.string() + "\n";
        return false;
    }
    std::string cmd = "cd \"" + repo.string() + "\" && md5sum -c hashes.md5";
    auto [rc, out] = run_command_capture(cmd);
    out_log += out;
    if (rc == 0) {
        out_log += "Integridad OK en " + repo.string() + "\n";
        return true;
    } else {
        out_log += "Integridad FALLIDA (rc=" + std::to_string(rc) + ") en " + repo.string() + "\n";
        return false;
    }
}

int main(int, char**)
{
    // Setup SDL + OpenGL context
    if (SDL_Init(SDL_INIT_VIDEO|SDL_INIT_TIMER|SDL_INIT_GAMECONTROLLER) != 0) {
        std::fprintf(stderr, "Error SDL_Init: %s\n", SDL_GetError());
        return 1;
    }

    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);

    SDL_Window* window = SDL_CreateWindow("Hash&GPG Manager - ImGui Prototype", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1000, 700, SDL_WINDOW_OPENGL|SDL_WINDOW_RESIZABLE);
    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1); // vsync

    // Initialize OpenGL loader (gl3w)
    if (gl3wInit() != 0) {
        std::fprintf(stderr, "Failed to initialize OpenGL loader!\n");
        return 1;
    }

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
    ImGui::StyleColorsDark();

    // Setup Platform/Renderer backends
    ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // App state
    char root_path_buf[1024] = "./";
    char gpg_key_buf[128] = "";
    std::string log_text;
    bool auto_scroll = true;

    bool running = true;
    while (running) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) running = false;
            if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window)) running = false;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame(window);
        ImGui::NewFrame();

        // Layout
        ImGui::Begin("Hash & GPG Manager");

        ImGui::InputText("Ruta raíz", root_path_buf, sizeof(root_path_buf));
        ImGui::InputText("GPG_KEY_ID (opcional)", gpg_key_buf, sizeof(gpg_key_buf));

        ImGui::Separator();

        // Detect repos
        ImGui::Text("Repos detectados:");
        static std::vector<fs::path> repos;
        repos.clear();
        try {
            for (auto& p : fs::directory_iterator(fs::path(root_path_buf))) {
                if (p.is_directory()) {
                    if (fs::exists(p.path() / ".git")) repos.push_back(p.path());
                }
            }
        } catch (const std::exception& e) {
            // ignore
        }

        for (size_t i=0;i<repos.size();++i) {
            ImGui::BulletText("%s", repos[i].string().c_str());
        }
        if (repos.empty()) ImGui::TextDisabled("No se encontraron repositorios (carpetas con .git) en la ruta.");

        ImGui::Separator();

        // Buttons
        if (ImGui::Button("Generar & Firmar (todos)")) {
            log_text += "=== Generar & Firmar ===\n";
            for (auto& r : repos) {
                log_text += "Procesando: " + r.string() + "\n";
                std::string tmp;
                if (!generate_hashes_md5(r, tmp)) {
                    log_text += "ERROR generando hashes en " + r.string() + "\n" + tmp + "\n";
                    continue;
                } else log_text += tmp;
                tmp.clear();
                if (!sign_hashes(r, std::string(gpg_key_buf), tmp)) {
                    log_text += "ERROR firmando en " + r.string() + "\n" + tmp + "\n";
                    continue;
                } else log_text += tmp;
                tmp.clear();
                if (!git_add_commit_push(r, tmp)) {
                    log_text += "ERROR git en " + r.string() + "\n" + tmp + "\n";
                    continue;
                } else log_text += tmp;
            }
            log_text += "=== Fin ===\n";
        }
        ImGui::SameLine();
        if (ImGui::Button("Verificar (todos)")) {
            log_text += "=== Verificar ===\n";
            for (auto& r : repos) {
                log_text += "Verificando: " + r.string() + "\n";
                std::string tmp;
                bool sigok = verify_signature(r, std::string(gpg_key_buf), tmp);
                log_text += tmp;
                tmp.clear();
                bool mdok = verify_md5sum(r, tmp);
                log_text += tmp;
                log_text += "Resultado: firma=" + std::string(sigok ? "OK" : "FAIL") + ", md5=" + std::string(mdok ? "OK" : "FAIL") + "\n";
            }
            log_text += "=== Fin verificación ===\n";
        }

        ImGui::Separator();

        ImGui::Checkbox("Auto-scroll", &auto_scroll);

        ImGui::BeginChild("LogWindow", ImVec2(0, 350), true, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::TextUnformatted(log_text.c_str());
        if (auto_scroll) ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();

        ImGui::End();

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        SDL_GL_GetDrawableSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.12f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();

    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();

    return 0;
}
