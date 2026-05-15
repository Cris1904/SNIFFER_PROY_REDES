#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <stdio.h>
#include <GLFW/glfw3.h> 

int main() {
    // 1. Inicializar GLFW
    if (!glfwInit()) return 1;

    // Configuración de versión de OpenGL (3.0 es estándar para compatibilidad)
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // 2. Crear ventana
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Prueba ImGui - Proyecto Redes I", NULL, NULL);
    if (window == NULL) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Habilitar V-Sync

    // 3. Inicializar Contexto de ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    // Configurar estilo (puedes usar Dark o Light)
    ImGui::StyleColorsDark();

    // 4. Inicializar Backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Bucle principal
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // Iniciar el Frame de ImGui
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // --- AQUÍ EMPIEZA TU INTERFAZ ---
        
        // Ventana de demostración para probar que todo funciona
        ImGui::ShowDemoWindow(); 

        // Ventana personalizada simple
        ImGui::Begin("Control de Sniffer"); 
        ImGui::Text("Estado: Configurando entorno grafico...");
        ImGui::Text("Segunda linea");
        if (ImGui::Button("Iniciar Captura")) {
            // Aquí irá tu lógica de Npcap más adelante
        }
        ImGui::End();

        // --- AQUÍ TERMINA TU INTERFAZ ---

        // Renderizado
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Limpieza
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}