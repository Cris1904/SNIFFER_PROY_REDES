/*----- LIBRERIAS DE ENTORNO GRÁFICO -----*/
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <stdio.h>
#include <GLFW/glfw3.h> 

#include <thread>
#include <vector>
#include <string>
#include "captura.h"

using namespace std;

/* ---- Variables globales ----*/
char ip_o[64] = "";
char ip_d[64] = "";
char proto[64] = "";
char puerto_d[64] = "";

/* ---- Menu de filtrado ---- */
void filtrado(){
  ImGui::Text("Filtrado de paquetes");
  ImGui::Text("IP Origen:"); ImGui::SameLine(); ImGui::SetNextItemWidth(120); ImGui::InputText("##ip_o", ip_o, IM_ARRAYSIZE(ip_o)); ImGui::SameLine();
  ImGui::Text("IP Destino:"); ImGui::SameLine(); ImGui::SetNextItemWidth(120); ImGui::InputText("##ip_d", ip_d, IM_ARRAYSIZE(ip_d)); ImGui::SameLine();
  ImGui::Text("Protocolo:"); ImGui::SameLine(); ImGui::SetNextItemWidth(80);  ImGui::InputText("##proto", proto, IM_ARRAYSIZE(proto)); ImGui::SameLine();
  ImGui::Text("Puerto destino:"); ImGui::SameLine(); ImGui::SetNextItemWidth(80);  ImGui::InputText("##p_d", puerto_d, IM_ARRAYSIZE(puerto_d));
}

/*----- INICIO DE FUNCIÓN MAIN (PRINCIPAL) -----*/
int main() {
  // 1. Inicializar GLFW
  if (!glfwInit()) return 1;

  const char* glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

  // 2. Crear ventana
  GLFWwindow* window = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes", NULL, NULL);
  if (window == NULL) return 1;
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1); 

  // 3. Inicializar Contexto de ImGui
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO(); (void)io;
  ImGui::StyleColorsClassic();

  // 4. Inicializar Backends
  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  // --- OBTENER INTERFACES PARA EL COMBO BOX DE IMGUI ---
  vector<string> lista_nombres_interfaces;
  pcap_if_t* alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (LoadNpcapDlls() && pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1) {
      for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
          if (d->description) {
              lista_nombres_interfaces.push_back(d->description);
          } else {
              lista_nombres_interfaces.push_back(d->name);
          }
      }
      pcap_freealldevs(alldevs);
  } else {
      lista_nombres_interfaces.push_back("Error al cargar interfaces de red");
  }

  int interfaz_seleccionada = 0; // Índice de la tarjeta de red elegida

  // Bucle principal
  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    // --- COMIENZA LA INTERFAZ GRAFICA  ---
    ImGui::Begin("Control de Sniffer"); 
    
    // Vemos si se estan capturando datos
    if (!captura_activa) {
      // En caso de que no se capturen
      ImGui::Text("Estado: Detenido");
      ImGui::Spacing();

      // Menu desplegable para seleccionar la interfaz
      if (ImGui::BeginCombo("Interfaz de Red", lista_nombres_interfaces[interfaz_seleccionada].c_str())) {
        for (int n = 0; n < lista_nombres_interfaces.size(); n++) {
          const bool is_selected = (interfaz_seleccionada == n);  /* Comprueba si el elemento actual es el seleccionado, si
                                                                  esta seleccionado entonces se hace true*/
          if (ImGui::Selectable(lista_nombres_interfaces[n].c_str(), is_selected)) {
            interfaz_seleccionada = n;
          }
          if (is_selected) {
            ImGui::SetItemDefaultFocus();
          }
        }
        ImGui::EndCombo();
      }

      ImGui::Spacing();
      if (ImGui::Button("Iniciar Captura", ImVec2(200, 30))) {
        // Se crea un hilo secundario para que Npcap capture y se pasa la interfaz seleccionada al hilo
        thread hilo_pcap(iniciar_hilo_captura, interfaz_seleccionada);
        // Se desenlaza el hilo del flujo principal para que corra en segundo plano
        hilo_pcap.detach(); 
      } 
      ImGui::Spacing();
      filtrado();
    }else {
      // En caso de que se capturen
      ImGui::Text("Estado: Capturando");
      ImGui::Text("Interfaz actual: %s", lista_nombres_interfaces[interfaz_seleccionada].c_str());
      ImGui::Spacing();

      if (ImGui::Button("Detener Captura", ImVec2(200, 30))) {
        if (adhandle_global != NULL) {
          pcap_breakloop(adhandle_global); // Se detiene el pcap_loop (la captura de datos)
          captura_activa = false; 
        }
      }
      ImGui::Spacing();
      filtrado();
    }
    ImGui::End();

    ImGui::Begin("Paquetes Capturados");
    if (ImGui::BeginTable("TablaPaquetes", 8, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
      // Definición de las etiquetas de cada columna
      ImGui::TableSetupColumn("Número de paquete");
      ImGui::TableSetupColumn("Tiempo de vida");
      ImGui::TableSetupColumn("Longitud (Bytes)");
      ImGui::TableSetupColumn("IP Origen");
      ImGui::TableSetupColumn("IP Destino");
      ImGui::TableSetupColumn("Protocolo");
      ImGui::TableSetupColumn("Puerto Origen");
      ImGui::TableSetupColumn("Puerto Destino");
      ImGui::TableHeadersRow(); 

      /* Bloqueamos el mutex antes de leer el vector. Esto evita que el hilo de captura intente escribir 
      al mismo tiempo que ImGui intenta leer */
      paquetes_mutex.lock();
      // Vamos sacando paquete por paquete que hay en este momento para ir mostrando en la tabla
      // Lo ponemos en auto para los distintos protocolos
      for (auto& pkt : lista_paquetes) {
        // Salta de fila automáticamente para el nuevo paquete
        ImGui::TableNextRow(); 
        // Distribuye cada campo en su columna
        ImGui::TableSetColumnIndex(0); ImGui::Text("%d", pkt.id);
        ImGui::TableSetColumnIndex(1); ImGui::Text("%s", pkt.tiempo_vida.c_str());
        ImGui::TableSetColumnIndex(2); ImGui::Text("%d", pkt.longitud);
        ImGui::TableSetColumnIndex(3); ImGui::Text("%s", pkt.IP_origen.c_str());
        ImGui::TableSetColumnIndex(4); ImGui::Text("%s", pkt.IP_destino.c_str());
        ImGui::TableSetColumnIndex(5); ImGui::Text("%s", pkt.protocolo.c_str());
        ImGui::TableSetColumnIndex(6); ImGui::Text("%s", pkt.Puerto_origen.c_str());
        ImGui::TableSetColumnIndex(7); ImGui::Text("%s", pkt.Puerto_destino.c_str());
      }
      
      if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()){
        ImGui::SetScrollHereY(1.0f); 
      }

      paquetes_mutex.unlock(); // Liberamos de inmediato el mutex para que el hilo de captura pueda seguir guardando paquetes

      ImGui::EndTable();
    }
    ImGui::End();

    // Renderizado
    ImGui::Render();
    int display_w, display_h;
    glfwGetFramebufferSize(window, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.15f, 0.16f, 0.21f, 1.00f); // Un fondo gris oscuro más estético
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