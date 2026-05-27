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
int idPaqueteSeleccionado = -1; // guarda el id del paquete seleccionado para su analisis (-1 = ninguno)

// ---- Menu de filtrado ----
void menuFiltrado()
{
  ImGui::Text("Filtrado de paquetes");
  ImGui::Text("IP Origen:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(120);
  ImGui::InputText("##ip_o", ip_o, IM_ARRAYSIZE(ip_o));
  ImGui::SameLine();
  ImGui::Text("IP Destino:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(120);
  ImGui::InputText("##ip_d", ip_d, IM_ARRAYSIZE(ip_d));
  ImGui::SameLine();
  ImGui::Text("Protocolo:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(80);
  ImGui::InputText("##proto", proto, IM_ARRAYSIZE(proto));
  ImGui::SameLine();
  ImGui::Text("Puerto destino:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(80);
  ImGui::InputText("##p_d", puerto_d, IM_ARRAYSIZE(puerto_d));
}

//----- INICIO DE LA FUNCIÓN PRINCIPAL -----
int main()
{
  // Inicializamos los graficos
  if (!glfwInit())
    return 1;
  const char *glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

  // Creamos la ventana grafica
  GLFWwindow *ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes", NULL, NULL);
  if (ventana == NULL)
    return 1;
  glfwMakeContextCurrent(ventana);
  glfwSwapInterval(1);

  // Inicializamos el entorno de ImGui
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  (void)io;
  ImGui::StyleColorsClassic();

  // Inicializamos los backends
  ImGui_ImplGlfw_InitForOpenGL(ventana, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  // OBTENEMOS LAS INTERFACES DISPONIBLES (PARA QUE EL USUARIO LAS OBSERVE Y SELECCIONE UNA)
  vector<string> listaInterfaces;
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (LoadNpcapDlls() && pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1)
  {
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next)
    {
      if (d->description)
      {
        listaInterfaces.push_back(d->description);
      }
      else
      {
        listaInterfaces.push_back(d->name);
      }
    }
    pcap_freealldevs(alldevs);
  }
  else
  {
    // Si no se encuentran interfaces
    listaInterfaces.push_back("Error al cargar interfaces de red");
  }

  int interfazSeleccionada = 0; // definimos el indice de la tarjeta de red elegida por default (la primera de la lista)

  // Bucle principal del analizador
  while (!glfwWindowShouldClose(ventana))
  {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    // Generamos la seccion grafica imgui para que el usuario maneje el tipo de interfaz asi como la captura y demas
    ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(800, 250), ImGuiCond_FirstUseEver);
    ImGui::Begin("Control de Sniffer");

    if (!captura_activa)
    {
      // Si no se estan capturando datos (estado por default) mostramos lo siguiente
      ImGui::Text("Estado: Detenido");
      ImGui::Spacing();

      // mostramos un menu desplegable (combo) para seleccionar la interfaz
      if (ImGui::BeginCombo("Interfaz de Red", listaInterfaces[interfazSeleccionada].c_str()))
      {
        for (int n = 0; n < listaInterfaces.size(); n++)
        {
          const bool esta_selecionada = (interfazSeleccionada == n); // verifica cual es la interfaz seleccionada del combo imgui
          if (ImGui::Selectable(listaInterfaces[n].c_str(), esta_selecionada))
          {
            interfazSeleccionada = n; // obtenemos el indice de la interfaz selecionada y lo asignamos a la variable para capturar
          }
          if (esta_selecionada)
          {
            ImGui::SetItemDefaultFocus(); // se muestra la interfaz selecionada
          }
        }
        ImGui::EndCombo(); // cerramos el espacio grafico de las opciones de interfaz
      }
      ImGui::Spacing();

      // mostramos un boton para iniciar la captura
      if (ImGui::Button("Iniciar Captura", ImVec2(200, 30)))
      {
        // Creamos un hilo para que Npcap capture (le indicamos cual es la interfaz seleccionada)
        thread hilo_pcap(iniciarCaptura, interfazSeleccionada);
        // Desenlazamos el hilo del flujo principal para que corra en segundo plano
        hilo_pcap.detach();
      }
      ImGui::Spacing(); // salto de linea
      menuFiltrado();   // mostramos menu para filtrar lo capturado
    }
    else
    {
      // En caso de que se esten capturando datos (al presionar el boton) se mostrara lo siguiente
      ImGui::Text("Estado: Capturando");
      ImGui::Text("Interfaz actual: %s", listaInterfaces[interfazSeleccionada].c_str()); // ya no se permite cambiar la interfaz solo mostramos la que fue selecionada
      ImGui::Spacing();

      // mostramos un boton para detener la captura
      if (ImGui::Button("Detener Captura", ImVec2(200, 30)))
      {
        if (adhandle_global != NULL)
        {
          pcap_breakloop(adhandle_global); // Se detiene el pcap_loop (la captura de datos)
          captura_activa = false;
        }
      }
      ImGui::Spacing();

      menuFiltrado(); // mostramos menu para filtrar lo capturado
    }
    ImGui::End(); // terminamos la primera seccion de la interfaz grafica imgui con "end"

    // iniciamos la segunda seccion grafica donde se muestra todo el trafico capturado
    ImGui::SetNextWindowPos(ImVec2(10, 270), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(800, 400), ImGuiCond_FirstUseEver);
    ImGui::Begin("Paquetes Capturados");
    
    if (ImGui::BeginTable("TablaPaquetes", 8, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
    {
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

      // Comienza el proceso para ver si hay algun filtro activo o no
      if (ip_o[0] == '\0' && ip_d[0] == '\0' && proto[0] == '\0' && puerto_d[0] == '\0')
      {
        // En caso de que no, vamos sacando paquete por paquete que hay en este momento para ir mostrando en la tabla
        // (Lo ponemos en auto para los distintos protocolos)
        for (auto &pkt : lista_paquetes)
        {
          // Salta de fila automaticamente para el nuevo paquete
          ImGui::TableNextRow();

          // Convertimos el ID a texto para compararlo
          ImGui::TableSetColumnIndex(0);
          char label_id[32];
          sprintf(label_id, "%d", pkt.id);

          // Comprobamos si esta fila es la que está seleccionada actualmente
          bool esta_seleccionado = (idPaqueteSeleccionado == pkt.id);

          // hacemos que el clic funcione en toda la fila (no solo una celda)
          if (ImGui::Selectable(label_id, esta_seleccionado, ImGuiSelectableFlags_SpanAllColumns))
          {
            // Si el usuario hace clic en la fila guardamos el ID del paquete
            idPaqueteSeleccionado = pkt.id;
          }

          // Distrimos cada campo en su columna
          ImGui::TableSetColumnIndex(0);
          ImGui::Text("%d", pkt.id);
          ImGui::TableSetColumnIndex(1);
          ImGui::Text("%s", pkt.tiempo_vida.c_str());
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%d", pkt.longitud);
          ImGui::TableSetColumnIndex(3);
          ImGui::Text("%s", pkt.IP_origen.c_str());
          ImGui::TableSetColumnIndex(4);
          ImGui::Text("%s", pkt.IP_destino.c_str());
          ImGui::TableSetColumnIndex(5);
          ImGui::Text("%s", pkt.protocolo.c_str());
          ImGui::TableSetColumnIndex(6);
          ImGui::Text("%s", pkt.Puerto_origen.c_str());
          ImGui::TableSetColumnIndex(7);
          ImGui::Text("%s", pkt.Puerto_destino.c_str());
        }
      }
      else
      {
        // En caso de que si, revisamos paquete por paquete para ver cuales cumplen con el filtro y solo mostrar esos
        // (Lo ponemos en auto para los distintos protocolos)
        for (auto &pkt : lista_paquetes)
        {
          if ((ip_o[0] != '\0' && strcmp(ip_o, pkt.IP_origen.c_str()) == 0) || (ip_d[0] != '\0' && strcmp(ip_d, pkt.IP_destino.c_str()) == 0) || (proto[0] != '\0' && strcmp(proto, pkt.protocolo.c_str()) == 0) || (puerto_d[0] != '\0' && strcmp(puerto_d, pkt.Puerto_destino.c_str()) == 0))
          {
            // Salta de fila automaticamente para el nuevo paquete
            ImGui::TableNextRow();
            // Distrimos cada campo en su columna
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%d", pkt.id);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", pkt.tiempo_vida.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%d", pkt.longitud);
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%s", pkt.IP_origen.c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%s", pkt.IP_destino.c_str());
            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%s", pkt.protocolo.c_str());
            ImGui::TableSetColumnIndex(6);
            ImGui::Text("%s", pkt.Puerto_origen.c_str());
            ImGui::TableSetColumnIndex(7);
            ImGui::Text("%s", pkt.Puerto_destino.c_str());
          }
        }
      }

      if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
      {
        ImGui::SetScrollHereY(1.0f);
      }

      paquetes_mutex.unlock(); // Liberamos el mutex para que el hilo de captura pueda seguir guardando paquetes

      ImGui::EndTable();
    }
    ImGui::End();

    // iniciamos la tercera seccion grafica donde se analiza cada uno de los paquetes del trafico
    ImGui::SetNextWindowPos(ImVec2(10, 670), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(800, 250), ImGuiCond_FirstUseEver);
    ImGui::Begin("Analisis del paquete");

    if (ImGui::BeginTable("TablaDetalles", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
    {
      // Definición de las etiquetas de cada columna
      ImGui::TableSetupColumn("Detalles del paquete", ImGuiTableColumnFlags_WidthFixed, 250.0f);
      ImGui::TableSetupColumn("Bytes del paquete");
      ImGui::TableHeadersRow();

      // Verificamos si hay un paquete seleccionado (es decir cuando tiene algo diferente de -1)
      if (idPaqueteSeleccionado != -1)
      {
        //Inicializamos el variables que analizan el paquete
        PaqueteInfo paquete_actual = {0, "", 0, "", "", "", "", ""};
        bool paquete_encontrado = false;

        // BLOQUEAMOS el mutex para leer el paquete de forma segura
        paquetes_mutex.lock();
        for (auto &pkt : lista_paquetes)
        {
          if (pkt.id == idPaqueteSeleccionado)
          {
            paquete_actual = pkt;
            paquete_encontrado = true;
            break;
          }
        }
        paquetes_mutex.unlock(); // DESBLOQUEAMOS el mutex

        // Si encontramos el paquete, mostramos sus datos
        if (paquete_encontrado)
        {
          ImGui::TableNextRow();

          ImGui::TableSetColumnIndex(0);
          ImGui::Text("Protocolo: %s", paquete_actual.protocolo.c_str());
          ImGui::Text("IP Origen: %s", paquete_actual.IP_origen.c_str());
          ImGui::Text("IP Destino: %s", paquete_actual.IP_destino.c_str());
          ImGui::Text("Puerto Origen: %s", paquete_actual.Puerto_origen.c_str());
          ImGui::Text("Puerto Destino: %s", paquete_actual.Puerto_destino.c_str());

          ImGui::TableSetColumnIndex(1);
          ImGui::Text("Longitud total capturada: %d bytes", paquete_actual.longitud);
          //Falta agregar codigo para que se muestre una matriz byte por byte 
        }
      }

      // Terminamos la tabla
      ImGui::EndTable();
    }
    ImGui::End();

    // Renderizado
    ImGui::Render();
    int display_w, display_h;
    glfwGetFramebufferSize(ventana, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.15f, 0.16f, 0.21f, 1.00f); // color de fondo
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