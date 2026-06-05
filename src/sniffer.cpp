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

#include <set>

using namespace std;

// ---- Variables globales ----
char ip_o[64] = "";
char ip_d[64] = "";
char proto[64] = "";
char puerto_d[64] = "";
int idPaqueteSeleccionado = -1;
static int protocolo_combo_idx = 0;

const char* lista_protocolos[] = {
  "Todos", "UDP", "DNS", "DHCP (Server)", "DHCP (Client)", "TFTP", "NTP", "SNMP", "Syslog",
  "TCP", "FTP (Data)", "FTP (Control)", "SSH / SFTP", "Telnet", "SMTP", "HTTP", 
  "POP3", "IMAP", "BGP", "LDAP", "HTTPS", "SMB", "SMTP (Seguro)", "LDAPS", "IMAPS"
};

// ---- Menu de filtrado ----
void menuFiltrado() {
  // Se guardaran en un set para evitar repetidas
  set<string> ips_origen_unicas;
  set<string> ips_destino_unicas;
  set<string>puertos_origen;
  set<string>puertos_destino;

  // Bloqueamos para extraer sin errores de escritura
  paquetes_mutex.lock();
  for (const auto& pkt : lista_paquetes) {
    if (!pkt.IP_origen.empty()) ips_origen_unicas.insert(pkt.IP_origen);
    if (!pkt.IP_destino.empty()) ips_destino_unicas.insert(pkt.IP_destino);
    if (!pkt.Puerto_origen.empty()) puertos_origen.insert(pkt.Puerto_origen);
    if (!pkt.Puerto_destino.empty()) puertos_destino.insert(pkt.Puerto_destino);
  }
  paquetes_mutex.unlock();

  ImGui::Text("Filtrado de paquetes");
  
  ImGui::Text("IP Origen:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(150);
  
  // Si la variable global 'ip_o' está vacía, mostramos "Todas"
  const char* ip_ori;
  if (ip_o[0] == '\0') {
    ip_ori = "Todas";
  } else {
    ip_ori = ip_o;
  } 
  
  if (ImGui::BeginCombo("##combo_ip_o", ip_ori)) {
    // Opción por defecto para limpiar el filtro
    bool o_todos_sel = (ip_o[0] == '\0');
    if (ImGui::Selectable("Todas", o_todos_sel)) {
      ip_o[0] = '\0';
    }
    
    // Listamos las IPs reales que han llegado
    for (const auto& ip : ips_origen_unicas) {
      bool esta_sel = (strcmp(ip_o, ip.c_str()) == 0);
      if (ImGui::Selectable(ip.c_str(), esta_sel)) {
        snprintf(ip_o, sizeof(ip_o), "%s", ip.c_str());
      }
    }
    ImGui::EndCombo();
  }

  ImGui::SameLine();
  ImGui::Text("IP Destino:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(150);

  const char* ip_des;
  if (ip_d[0] == '\0') {
    ip_des = "Todas";
  } else {
    ip_des = ip_d;
  }

  if (ImGui::BeginCombo("##combo_ip_d", ip_des)){
    // Opción por defecto para limpiar el filtro
    bool d_todos_sel = (ip_d[0] == '\0');
    if (ImGui::Selectable("Todas", d_todos_sel)) {
      ip_d[0] = '\0';
    }
    
    // Listamos las IPs reales que han llegado
    for (const auto& ip : ips_destino_unicas) {
      bool esta_sel = (strcmp(ip_d, ip.c_str()) == 0);
      if (ImGui::Selectable(ip.c_str(), esta_sel)) {
        snprintf(ip_d, sizeof(ip_d), "%s", ip.c_str());
      }
    }
    ImGui::EndCombo();
  }
  
  ImGui::SameLine();
  ImGui::Text("Protocolo:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(140);
  if (ImGui::BeginCombo("##proto_combo", lista_protocolos[protocolo_combo_idx])){
    for (int n = 0; n < IM_ARRAYSIZE(lista_protocolos); n++){
      const bool esta_seleccionado = (protocolo_combo_idx == n);
      if (ImGui::Selectable(lista_protocolos[n], esta_seleccionado))
      {
        protocolo_combo_idx = n;
        
        // Si selecciona "Todos", vaciamos la cadena para desactivar el filtro de protocolo
        if (n == 0) {
          proto[0] = '\0'; 
        } else {
          // Copiamos el nombre del protocolo seleccionado a la variable global 'proto'
          snprintf(proto, sizeof(proto), "%s", lista_protocolos[n]);
        }
      }
      
      if (esta_seleccionado) {
        ImGui::SetItemDefaultFocus();
      }
    }
    ImGui::EndCombo();
  }

  ImGui::SameLine();
  ImGui::Text("Puerto destino:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(80);

  const char* puerto_des;
  if (puerto_d[0] == '\0') {
    puerto_des = "Todos";
  } else {
    puerto_des = puerto_d;
  } 
  
  if (ImGui::BeginCombo("##combo_puertos_des", puerto_des)) {
    // Opción por defecto para limpiar el filtro
    bool p_todos_sel = (puerto_d[0] == '\0');
    if (ImGui::Selectable("Todos", p_todos_sel)) {
      puerto_d[0] = '\0';
    }
    
    for (const auto& puerto : puertos_destino) {
      bool esta_sel = (strcmp(puerto_d, puerto.c_str()) == 0);
      if (ImGui::Selectable(puerto.c_str(), esta_sel)) {
        snprintf(puerto_d, sizeof(puerto_d), "%s", puerto.c_str());
      }
    }
    ImGui::EndCombo();
  }
}

//----- INICIO DE LA FUNCIÓN PRINCIPAL -----
int main()
{
  // Inicializamos los graficos
  if (!glfwInit())
    return 1;
  const char *glsl_version = "#version 130";
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);

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

    // Obtener el tamaño actual de la ventana
    ImVec2 viewportSize = ImGui::GetIO().DisplaySize;

    // Definimos márgenes y alturas relativas
    float padding = 10.0f;
    float altoControl = viewportSize.y * 0.2f;
    float altoTabla = viewportSize.y * 0.45f;
    float altoAnalisis = viewportSize.y * 0.3f;

    // Generamos la seccion grafica imgui para que el usuario maneje el tipo de interfaz asi como la captura y demas
    ImGui::SetNextWindowPos(ImVec2(padding, padding));
    ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoControl));
    ImGui::Begin("Control de Sniffer", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

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
    ImGui::SetNextWindowPos(ImVec2(padding, padding + altoControl + padding));
    ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoTabla));
    ImGui::Begin("Paquetes Capturados", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

    if (ImGui::BeginTable("TablaPaquetes", 8, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
    {
      // Definición de las etiquetas de cada columna
      ImGui::TableSetupScrollFreeze(0, 1);
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
      else {
        // En caso de que sí haya filtros
        for (auto &pkt : lista_paquetes) {
          // Filtros: Si el campo del filtro está vacío o coincide con el valor del paquete, se muestra el paquete
          if ((ip_o[0] == '\0' || strcmp(ip_o, pkt.IP_origen.c_str()) == 0) &&
            (ip_d[0] == '\0' || strcmp(ip_d, pkt.IP_destino.c_str()) == 0) &&
            (proto[0] == '\0' || strcmp(proto, pkt.protocolo.c_str()) == 0) &&
            (puerto_d[0] == '\0' || strcmp(puerto_d, pkt.Puerto_destino.c_str()) == 0)) 
          {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            char label_id[32];
            sprintf(label_id, "%d", pkt.id);
            bool esta_seleccionado = (idPaqueteSeleccionado == pkt.id);

            // Permitir la selección también cuando el filtro está activo
            if (ImGui::Selectable(label_id, esta_seleccionado, ImGuiSelectableFlags_SpanAllColumns)) {
              idPaqueteSeleccionado = pkt.id;
            }

            // Imprimir el resto de columnas
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
    ImGui::SetNextWindowPos(ImVec2(padding, padding + altoControl + padding + altoTabla + padding));
    ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoAnalisis));
    ImGui::Begin("Analisis del paquete", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

    if (ImGui::BeginTable("TablaDetalles", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY ))
    {
      // Definición de las etiquetas de cada columna
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableSetupColumn("Detalles del paquete", ImGuiTableColumnFlags_WidthFixed);
      ImGui::TableSetupColumn("Bytes del paquete");
      ImGui::TableHeadersRow();

      // Verificamos si hay un paquete seleccionado (es decir cuando tiene algo diferente de -1)
      if (idPaqueteSeleccionado != -1)
      {
        //Inicializamos el variables que analizan el paquete
        PaqueteInfo paquete_actual = {0, "", 0, "", "", "", "", "", 0, "", "",nullptr, 0};
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
          ImGui::TableSetColumnIndex(0); // Columna de detalles

          // 1. Capa física (Trama)
          string titulo_trama = "Trama " + to_string(paquete_actual.id);
          if (ImGui::TreeNode(titulo_trama.c_str())) {
            ImGui::Text("Hora de llegada: %s", paquete_actual.tiempo_vida.c_str());
            ImGui::Text("Longitud: %d bytes", paquete_actual.longitud);
            ImGui::TreePop();
          }

          // 2. Capa de enlace (Ethernet)
          if (ImGui::TreeNode("Ethernet II")) {
            ImGui::Text("MAC Destino: %s", paquete_actual.mac_destino.c_str());
            ImGui::Text("MAC Origen:  %s", paquete_actual.mac_origen.c_str());
            ImGui::TreePop();
          }

          // 3. Capa de red (IPv4)
          string titulo_ip = "IPv4";
          if (ImGui::TreeNode(titulo_ip.c_str())) {
            ImGui::Text("IP Origen:  %s", paquete_actual.IP_origen.c_str());
            ImGui::Text("IP Destino: %s", paquete_actual.IP_destino.c_str());
            ImGui::Text("Tiempo de vida (TTL): %d", paquete_actual.ttl);
            ImGui::TreePop();
          }

          // 4. Capa de transporte (TCP/UDP)
          string titulo_puertos = "Protocolo de transporte (" + paquete_actual.protocolo + ")";
          if (ImGui::TreeNode(titulo_puertos.c_str())) {
            ImGui::Text("Puerto Origen:  %s", paquete_actual.Puerto_origen.c_str());
            ImGui::Text("Puerto Destino: %s", paquete_actual.Puerto_destino.c_str());
            ImGui::TreePop();
          }

          if (paquete_actual.mostrar_dns) {
            if (ImGui::TreeNode("Análisis DNS")) {
              ImGui::Text("Dominio consultado: %s", paquete_actual.nombre_dns.c_str());
              ImGui::TreePop();
            }
          }

          // Columna derecha: Bytes Raw 
          ImGui::TableSetColumnIndex(1);
          ImGui::SeparatorText("Contenido del Paquete Hexadecimal");
          
          ImGui::BeginChild("HexDumpRegion", ImVec2(0, 180), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
          
          string hex_line;
          string ascii_line;
          for (size_t i = 0; i < paquete_actual.raw_data.size(); i++) {
              char hex_buf[4];
              sprintf(hex_buf, "%02X ", paquete_actual.raw_data[i]);
              hex_line += hex_buf;
              
              // Representación ASCII (reemplaza caracteres no imprimibles por un punto)
              char c = paquete_actual.raw_data[i];
              ascii_line += (c >= 32 && c <= 126) ? c : '.';

              // Imprimir línea cada 16 bytes o al final del paquete
              if ((i + 1) % 16 == 0 || i == paquete_actual.raw_data.size() - 1) {
                  // Rellenar espacios si la última línea es más corta
                  while (hex_line.length() < 16 * 3) hex_line += "   ";
                  
                  // Formato: Offset | Hexadecimal | ASCII
                  ImGui::Text("%04zX  %s | %s", (i / 16) * 16, hex_line.c_str(), ascii_line.c_str());
                  hex_line = "";
                  ascii_line = "";
              }
          }
          ImGui::EndChild();
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