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

// ---- Variables globales ----
char ip_o[64] = "";
char ip_d[64] = "";
char proto[64] = "";
char puerto_d[64] = "";

// ---- Menu de filtrado ---- 
void menuFiltrado(){
  ImGui::Text("Filtrado de paquetes");
  ImGui::Text("IP Origen:"); ImGui::SameLine(); ImGui::SetNextItemWidth(120); ImGui::InputText("##ip_o", ip_o, IM_ARRAYSIZE(ip_o)); ImGui::SameLine();
  ImGui::Text("IP Destino:"); ImGui::SameLine(); ImGui::SetNextItemWidth(120); ImGui::InputText("##ip_d", ip_d, IM_ARRAYSIZE(ip_d)); ImGui::SameLine();
  ImGui::Text("Protocolo:"); ImGui::SameLine(); ImGui::SetNextItemWidth(80);  ImGui::InputText("##proto", proto, IM_ARRAYSIZE(proto)); ImGui::SameLine();
  ImGui::Text("Puerto destino:"); ImGui::SameLine(); ImGui::SetNextItemWidth(80);  ImGui::InputText("##p_d", puerto_d, IM_ARRAYSIZE(puerto_d));
}

//----- INICIO DE LA FUNCIÓN PRINCIPAL -----
int main() {
  // Inicializamos los graficos
  if (!glfwInit()) return 1;
  const char* glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

  // Creamos la ventana grafica
  GLFWwindow* ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes", NULL, NULL);
  if (ventana == NULL) return 1;
  glfwMakeContextCurrent(ventana);
  glfwSwapInterval(1); 

  // Inicializamos el entorno de ImGui
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO(); (void)io;
  ImGui::StyleColorsClassic();

  // Inicializamos los backends
  ImGui_ImplGlfw_InitForOpenGL(ventana, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  // OBTENEMOS LAS INTERFACES DISPONIBLES (PARA QUE EL USUARIO LAS OBSERVE Y SELECCIONE UNA)
  vector<string> listaInterfaces;
  pcap_if_t* alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (LoadNpcapDlls() && pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1) {
      for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
          if (d->description) {
              listaInterfaces.push_back(d->description);
          } else {
              listaInterfaces.push_back(d->name);
          }
      }
      pcap_freealldevs(alldevs);
  } else {
      //Si no se encuentran interfaces 
      listaInterfaces.push_back("Error al cargar interfaces de red");
  }

  int interfazSeleccionada = 0; //definimos el indice de la tarjeta de red elegida por default (la primera de la lista)

  // Bucle principal del analizador
  while (!glfwWindowShouldClose(ventana)) {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    // Iniciamos la primera seccion de la interfaz grafica imgui con "begin"
    ImGui::Begin("Control de Sniffer"); 
    
    if (!captura_activa) {
      // Si no se estan capturando datos (estado por default) mostramos lo siguiente
      ImGui::Text("Estado: Detenido");
      ImGui::Spacing();

      // mostramos un menu desplegable (combo) para seleccionar la interfaz
      if (ImGui::BeginCombo("Interfaz de Red", listaInterfaces[interfazSeleccionada].c_str())) {
        for (int n = 0; n < listaInterfaces.size(); n++) {
          const bool esta_selecionada = (interfazSeleccionada == n);  //verifica cual es la interfaz seleccionada del combo imgui
          if (ImGui::Selectable(listaInterfaces[n].c_str(), esta_selecionada)) {
            interfazSeleccionada = n; //obtenemos el indice de la interfaz selecionada y lo asignamos a la variable para capturar
          }
          if (esta_selecionada) {
            ImGui::SetItemDefaultFocus(); //se muestra la interfaz selecionada
          }
        }
        ImGui::EndCombo(); //cerramos el espacio grafico de las opciones de interfaz
      }
      ImGui::Spacing();

      //mostramos un boton para iniciar la captura 
      if (ImGui::Button("Iniciar Captura", ImVec2(200, 30))) {
        // Creamos un hilo para que Npcap capture (le indicamos cual es la interfaz seleccionada)
        thread hilo_pcap(iniciarCaptura, interfazSeleccionada);
        // Desenlazamos el hilo del flujo principal para que corra en segundo plano
        hilo_pcap.detach(); 
      } 
      ImGui::Spacing(); //salto de linea
      menuFiltrado(); //mostramos menu para filtrar lo capturado

    }else {
      // En caso de que se esten capturando datos (al presionar el boton) se mostrara lo siguiente
      ImGui::Text("Estado: Capturando");
      ImGui::Text("Interfaz actual: %s", listaInterfaces[interfazSeleccionada].c_str()); //ya no se permite cambiar la interfaz solo mostramos la que fue selecionada 
      ImGui::Spacing();

      //mostramos un boton para detener la captura
      if (ImGui::Button("Detener Captura", ImVec2(200, 30))) {
        if (adhandle_global != NULL) {
          pcap_breakloop(adhandle_global); // Se detiene el pcap_loop (la captura de datos)
          captura_activa = false; 
        }
      }
      ImGui::Spacing();

      menuFiltrado();//mostramos menu para filtrar lo capturado
    }
    ImGui::End(); //terminamos la primera seccion de la interfaz grafica imgui con "end"

    //iniciamos otra seccion grafica con begin
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

      /* Bloqueamos el mutex antes de leer el vector (para que el hilo de captura no intente escribir 
      al mismo tiempo que ImGui intenta leer) */
      paquetes_mutex.lock();
      // Vamos sacando paquete por paquete que hay en este momento para ir mostrando en la tabla
      // (Lo ponemos en auto para los distintos protocolos)
      for (auto& pkt : lista_paquetes) {
        // Salta de fila automaticamente para el nuevo paquete
        ImGui::TableNextRow(); 
        // Distrimos cada campo en su columna
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

      paquetes_mutex.unlock(); // Liberamos el mutex para que el hilo de captura pueda seguir guardando paquetes

      ImGui::EndTable();
    }
    ImGui::End();

    // Renderizado
    ImGui::Render();
    int display_w, display_h;
    glfwGetFramebufferSize(ventana, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.15f, 0.16f, 0.21f, 1.00f); //color de fondo
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwSwapBuffers(ventana);
  }

  // Limpieza
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(ventana);
  glfwTerminate();

  return 0;
}