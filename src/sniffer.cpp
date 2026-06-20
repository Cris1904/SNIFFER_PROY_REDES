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
#include <map>

using namespace std;

// Estructura para almacenar información detallada de los adaptadores
struct InterfazRedInfo {
    string nombre_original; // Guarda el identificador interno de Windows (\Device\NPF_{GUID})
    string descripcion;     // Guarda la descripción cruda de Npcap (Realtek PCIe GbE...)
    string nombre_amigable; // Aquí guardaremos el nombre amigable para el usuario (Wi-Fi)
};

// ---- Estados del programa (ventanas) ----
enum EstadoPantalla {
  PANTALLA_INICIO,
  VENTANA_AYUDA,
  SNIFFER
};
EstadoPantalla estado_actual = PANTALLA_INICIO;
EstadoPantalla estado_anterior = PANTALLA_INICIO; // Variable para saber a dónde regresar

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

ImU32 ObtenerColorProtocolo(const std::string& protocolo) {
  if (protocolo == "TCP")   return ImGui::ColorConvertFloat4ToU32(ImVec4(0.2f, 0.5f, 0.9f, 0.25f)); // Azul
  if (protocolo == "UDP")   return ImGui::ColorConvertFloat4ToU32(ImVec4(0.9f, 0.6f, 0.1f, 0.25f)); // Naranja
  if (protocolo == "DNS")   return ImGui::ColorConvertFloat4ToU32(ImVec4(0.3f, 0.8f, 0.4f, 0.25f)); // Verde
  if (protocolo == "HTTP")  return ImGui::ColorConvertFloat4ToU32(ImVec4(0.8f, 0.3f, 0.8f, 0.25f)); // Púrpura
  if (protocolo == "HTTPS") return ImGui::ColorConvertFloat4ToU32(ImVec4(0.9f, 0.2f, 0.2f, 0.25f)); // Rojo
  
  return ImGui::ColorConvertFloat4ToU32(ImVec4(0.3f, 0.3f, 0.3f, 0.2f)); 
}

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

  // Obtenemos las interfaces disponibles y utilizamos la nueva estructura para almacenar su información
  vector<InterfazRedInfo> listaInterfaces;
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (LoadNpcapDlls() && pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1)
  {
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next)
    {
      InterfazRedInfo info;
      info.nombre_original = d->name ? d->name : "";
      info.descripcion = d->description ? d->description : "Sin descripción";
      // Preparamos temporalmente el nombre amigable concatenando la descripcion que obtenemos.
      // Nota: luego reemplazaremos este codigo para extraer el registro real de Windows.
      info.nombre_amigable = "[Nombre amigable] " + info.descripcion; 

      listaInterfaces.push_back(info);
    }
    pcap_freealldevs(alldevs);
  }
  else
  {
    InterfazRedInfo err_info;
    err_info.nombre_amigable = "Error al cargar interfaces de red";
    listaInterfaces.push_back(err_info);
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

    // Definimos la logica de las ventanas
    if (estado_actual == PANTALLA_INICIO) {
        // --- PANTALLA DE INICIO ---
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(viewportSize);
        ImGui::Begin("Pantalla de Inicio", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBackground);

        float windowWidth = ImGui::GetWindowSize().x;

        // Título del proyecto
        ImGui::SetCursorPosY(20.0f);
        const char* titulo = "SNIFFER - PROYECTO DE REDES";
        ImGui::SetWindowFontScale(2.0f); 
        float textWidth = ImGui::CalcTextSize(titulo).x;
        ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
        ImGui::TextUnformatted(titulo);
        ImGui::SetWindowFontScale(1.0f); 
        
        // Empujamos los botones hacia el centro de la pantalla
        ImGui::SetCursorPosY(viewportSize.y * 0.35f); 

        // Configuramos tamaño de los botones 
        float btnWidth = 300.0f;
        float btnHeight = 60.0f;

        ImGui::SetWindowFontScale(1.5f);

        // Botón para entrar al Sniffer
        ImGui::SetCursorPosX((windowWidth - btnWidth) * 0.5f);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.5f, 0.9f, 1.0f)); // Azul
        if (ImGui::Button("Entrar al Sniffer", ImVec2(btnWidth, btnHeight))) {
            estado_actual = SNIFFER;
        }
        ImGui::PopStyleColor();
        ImGui::Spacing(); ImGui::Spacing();

        // Botón para Menú de Ayuda
        ImGui::SetCursorPosX((windowWidth - btnWidth) * 0.5f);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.4f, 0.4f, 0.4f, 1.0f)); // Gris
        if (ImGui::Button("Menu de Ayuda", ImVec2(btnWidth, btnHeight))) {
            estado_anterior = PANTALLA_INICIO; // Guardamos que venimos del inicio
            estado_actual = VENTANA_AYUDA;
        }
        ImGui::PopStyleColor();
        
        ImGui::SetWindowFontScale(1.0f); // Restauramos la escala de la fuente

        ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
        
        // Sección de nuestros creditos
        const char* label_devs = "Programa desarrollado por:";
        float devWidth = ImGui::CalcTextSize(label_devs).x;
        ImGui::SetCursorPosX((windowWidth - devWidth) * 0.5f);
        ImGui::TextUnformatted(label_devs);
        
        const char* dev1 = "- Tania Jaquelin Lopez Acevedo";
        const char* dev2 = "- Antonio Duron Mendoza";
        const char* dev3 = "- Ulises Raygoza Castaneda";
        const char* dev4 = "- Cristian de Jesus Vazquez Delgado";
        const char* dev5 = "Correo de contacto: equipoumisumi4321@gmail.com";

        // Centramos los nombres basándonos en el más largo
        float maxDevWidth = ImGui::CalcTextSize(dev1).x;
        ImGui::SetCursorPosX((windowWidth - maxDevWidth) * 0.5f);
        ImGui::TextUnformatted(dev1);
        ImGui::SetCursorPosX((windowWidth - maxDevWidth) * 0.5f);
        ImGui::TextUnformatted(dev2);
        ImGui::SetCursorPosX((windowWidth - maxDevWidth) * 0.5f);
        ImGui::TextUnformatted(dev3);
        ImGui::SetCursorPosX((windowWidth - maxDevWidth) * 0.5f);
        ImGui::TextUnformatted(dev4);

        // Agregamos un poco de espacio y centramos el correo
        ImGui::Spacing(); ImGui::Spacing();
        float dev5Width = ImGui::CalcTextSize(dev5).x;
        ImGui::SetCursorPosX((windowWidth - dev5Width) * 0.5f);
        ImGui::TextUnformatted(dev5);

        ImGui::End();
    } 
    else if (estado_actual == VENTANA_AYUDA) {
        // --- PANTALLA DE AYUDA ---
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(viewportSize);
        ImGui::Begin("Ventana de Ayuda", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

        float windowWidthAyuda = ImGui::GetWindowSize().x;

        // Título del menú de ayuda
        ImGui::SetCursorPosY(20.0f);
        const char* tituloAyuda = "MENU DE AYUDA";
        ImGui::SetWindowFontScale(2.5f); 
        float helpTextWidth = ImGui::CalcTextSize(tituloAyuda).x;
        ImGui::SetCursorPosX((windowWidthAyuda - helpTextWidth) * 0.5f);
        ImGui::TextUnformatted(tituloAyuda);

        ImGui::SetWindowFontScale(1.4f); 

        ImGui::Spacing(); ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        // Contenedor interno para las instrucciones
        ImGui::BeginChild("Instrucciones", ImVec2(0, viewportSize.y - 140.0f), false);
        
        ImGui::TextWrapped("Conoce tu Sniffer. Este programa te permite ver y analizar el tráfico de red. A continuación te explicamos cómo funciona cada sección para que aproveches al maximo sus funciones:");
        ImGui::Spacing(); ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.7f, 0.3f, 1.0f)); // Verde
        ImGui::Text("1. Control de Captura (Parte Superior)");
        ImGui::PopStyleColor();
        ImGui::BulletText("Interfaz de Red: Selecciona del menu desplegable el adaptador que quieres 'escuchar' (puede ser tu tarjeta Wi-Fi, Ethernet, etc.).");
        ImGui::BulletText("Botones Iniciar/Detener: Haz clic en Iniciar para que el programa empiece a capturar datos en tiempo real y Detener para terminar la captura de trafico.");
        ImGui::BulletText("Filtros: Puedes escribir o seleccionar IPs y protocolos (como DNS o HTTP) que te interesen para realizar tu trabajo con mas facilidad y rapidez.");
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.5f, 0.9f, 1.0f)); // Azul
        ImGui::Text("2. Tabla de Paquetes Capturados (Parte Central)");
        ImGui::PopStyleColor();
        ImGui::BulletText("Aquí se enlista cada 'paquete' de información que viaja por la red.");
        ImGui::BulletText("NOTA: puedes hacer clic izquierdo sobre cualquier fila de esta tabla para seleccionar un paquete específico y poder analizarlo en la seccion numero 3.");
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.3f, 0.8f, 1.0f)); // Púrpura
        ImGui::Text("3. Análisis del Paquete (Parte Inferior)");
        ImGui::PopStyleColor();
        ImGui::BulletText("Detalles (Izquierda): Muestra el desglose técnico del paquete seleccionado. Puedes expandir cada capa haciendo clic en las flechitas.");
        ImGui::BulletText("Bytes del Paquete (Derecha): Es la información en estado puro. Muestra los datos tal como viajan por la red en formato Hexadecimal (números y letras) y su traducción a texto legible (ASCII).");
        
        ImGui::BulletText("\nPara mas información, comunicate con los desarrolladores, mandando un correo a la cuenta gmail que aparece en la parte inferior del menu principal");

        ImGui::EndChild();

        ImGui::SetWindowFontScale(1.5f);

        // Botón "Volver" centrado y hasta abajo
        float btnVolverWidth = 200.0f;
        float btnVolverHeight = 50.0f; 
        
        ImGui::SetCursorPosY(viewportSize.y - btnVolverHeight - 20.0f);
        ImGui::SetCursorPosX((windowWidthAyuda - btnVolverWidth) * 0.5f);

        if (ImGui::Button("Volver", ImVec2(btnVolverWidth, btnVolverHeight))) {
            estado_actual = estado_anterior; 
        }

        ImGui::SetWindowFontScale(1.0f);

        ImGui::End();
    }
    else if (estado_actual == SNIFFER) {
        // --- PANTALLA PRINCIPAL DEL SNIFFER ---
        
        float padding = 10.0f;
        float altoControl = viewportSize.y * 0.2f;
        float altoTabla = viewportSize.y * 0.45f;
        float altoAnalisis = viewportSize.y * 0.3f;

        ImGui::SetNextWindowPos(ImVec2(padding, padding));
        ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoControl));
        ImGui::Begin("Control de Sniffer", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);
        
        float controlWindowWidth = ImGui::GetWindowSize().x;
        float btnVolverWidth = 100.0f;
        float btnAyudaWidth = 100.0f;
        float espaciadoBotones = ImGui::GetStyle().ItemSpacing.x;
        float margenDerecho = 15.0f;
        
        ImGui::SetCursorPosX(controlWindowWidth - btnVolverWidth - btnAyudaWidth - espaciadoBotones - margenDerecho);

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.5f, 0.9f, 1.0f));        
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.1f, 0.3f, 0.7f, 1.0f)); 
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.0f, 0.2f, 0.5f, 1.0f));  
        
        // Habilitar o deshabilitar el boton "volver" para evitar cierres accidentales durante la captura
        if (captura_activa) {
            ImGui::BeginDisabled();
        }

        if (ImGui::Button("Volver", ImVec2(btnVolverWidth, 0))) {
            estado_actual = PANTALLA_INICIO;
        }

        if (captura_activa) {
            ImGui::EndDisabled(); 

            // Mensaje flotante indicando por qué está deshabilitado
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
                ImGui::SetTooltip("Por favor, deten la captura de trafico antes de volver al menu principal.");
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Ayuda", ImVec2(btnAyudaWidth, 0))) {
            estado_anterior = SNIFFER; 
            estado_actual = VENTANA_AYUDA;
        }
        
        ImGui::PopStyleColor(3); 
        
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        if (!captura_activa)
        {
          ImGui::Text("Estado: Detenido");
          ImGui::Spacing();

          // Llenamos la lista desplegable con los nombres amigables que procesamos previamente en la estructura
          if (ImGui::BeginCombo("Interfaz de Red", listaInterfaces[interfazSeleccionada].nombre_amigable.c_str()))
          {
            for (int n = 0; n < listaInterfaces.size(); n++)
            {
              const bool esta_selecionada = (interfazSeleccionada == n); 
              if (ImGui::Selectable(listaInterfaces[n].nombre_amigable.c_str(), esta_selecionada))
              {
                interfazSeleccionada = n; 
              }
              if (esta_selecionada)
              {
                ImGui::SetItemDefaultFocus();
              }
            }
            ImGui::EndCombo(); 
          }
          ImGui::Spacing();

          ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.7f, 0.3f, 1.0f)); // Verde
          if (ImGui::Button("Iniciar Captura", ImVec2(200, 30)))
          {
            thread hilo_pcap(iniciarCaptura, interfazSeleccionada);
            hilo_pcap.detach();
          }
          ImGui::PopStyleColor();
          ImGui::Spacing(); 
          menuFiltrado(); 
        }
        else
        {
          ImGui::Text("Estado: Capturando");
          ImGui::Text("Interfaz actual: %s", listaInterfaces[interfazSeleccionada].nombre_amigable.c_str()); 
          ImGui::Spacing();

          ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.1f, 0.1f, 1.0f)); // Rojo
          if (ImGui::Button("Detener Captura", ImVec2(200, 30)))
          {
            if (adhandle_global != NULL)
            {
              pcap_breakloop(adhandle_global); 
              captura_activa = false;
            }
          }
          ImGui::PopStyleColor();
          ImGui::Spacing();

          menuFiltrado(); 
        }
        ImGui::End(); 

        // iniciamos la segunda seccion grafica donde se muestra todo el trafico capturado
        ImGui::SetNextWindowPos(ImVec2(padding, padding + altoControl + padding));
        ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoTabla));
        ImGui::Begin("Paquetes Capturados", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

        if (ImGui::BeginTable("TablaPaquetes", 8, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
        {
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

          paquetes_mutex.lock();

          if (ip_o[0] == '\0' && ip_d[0] == '\0' && proto[0] == '\0' && puerto_d[0] == '\0')
          {
            for (auto &pkt : lista_paquetes)
            {
              ImGui::TableNextRow();

              ImU32 color_fila = ObtenerColorProtocolo(pkt.protocolo);
              ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, color_fila);

              ImGui::TableSetColumnIndex(0);
              char label_id[32];
              sprintf(label_id, "%d", pkt.id);

              bool esta_seleccionado = (idPaqueteSeleccionado == pkt.id);

              if (ImGui::Selectable(label_id, esta_seleccionado, ImGuiSelectableFlags_SpanAllColumns))
              {
                idPaqueteSeleccionado = pkt.id;
              }

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
            for (auto &pkt : lista_paquetes) {
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

                if (ImGui::Selectable(label_id, esta_seleccionado, ImGuiSelectableFlags_SpanAllColumns)) {
                  idPaqueteSeleccionado = pkt.id;
                }

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

          paquetes_mutex.unlock(); 

          ImGui::EndTable();
        }
        ImGui::End();

        // iniciamos la tercera seccion grafica donde se analiza cada uno de los paquetes del trafico
        ImGui::SetNextWindowPos(ImVec2(padding, padding + altoControl + padding + altoTabla + padding));
        ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoAnalisis));
        ImGui::Begin("Analisis del paquete", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

        if (ImGui::BeginTable("TablaDetalles", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY ))
        {
          ImGui::TableSetupScrollFreeze(0, 1);
          ImGui::TableSetupColumn("Detalles del paquete", ImGuiTableColumnFlags_WidthFixed);
          ImGui::TableSetupColumn("Bytes del paquete");
          ImGui::TableHeadersRow();

          if (idPaqueteSeleccionado != -1)
          {
            PaqueteInfo paquete_actual = {0, "", 0, "", "", "", "", "", 0, "", "",nullptr, 0};
            bool paquete_encontrado = false;

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
            paquetes_mutex.unlock(); 
            
            if (paquete_encontrado)
            {
              ImGui::TableNextRow();
              ImGui::TableSetColumnIndex(0); 

              string titulo_trama = "Trama " + to_string(paquete_actual.id);
              if (ImGui::TreeNode(titulo_trama.c_str())) {
                ImGui::Text("Hora de llegada: %s", paquete_actual.tiempo_vida.c_str());
                ImGui::Text("Longitud: %d bytes", paquete_actual.longitud);
                ImGui::TreePop();
              }

              if (ImGui::TreeNode("Ethernet II")) {
                ImGui::Text("MAC Destino: %s", paquete_actual.mac_destino.c_str());
                ImGui::Text("MAC Origen:  %s", paquete_actual.mac_origen.c_str());
                ImGui::TreePop();
              }

              string titulo_ip = "IPv4";
              if (ImGui::TreeNode(titulo_ip.c_str())) {
                ImGui::Text("IP Origen:  %s", paquete_actual.IP_origen.c_str());
                ImGui::Text("IP Destino: %s", paquete_actual.IP_destino.c_str());
                ImGui::Text("Tiempo de vida (TTL): %d", paquete_actual.ttl);
                ImGui::TreePop();
              }

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

              ImGui::TableSetColumnIndex(1);
              ImGui::SeparatorText("Contenido del Paquete Hexadecimal");
              
              ImGui::BeginChild("HexDumpRegion", ImVec2(0, 180), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
              
              string hex_line;
              string ascii_line;
              for (size_t i = 0; i < paquete_actual.raw_data.size(); i++) {
                  char hex_buf[4];
                  sprintf(hex_buf, "%02X ", paquete_actual.raw_data[i]);
                  hex_line += hex_buf;
                  
                  char c = paquete_actual.raw_data[i];
                  ascii_line += (c >= 32 && c <= 126) ? c : '.';

                  if ((i + 1) % 16 == 0 || i == paquete_actual.raw_data.size() - 1) {
                      while (hex_line.length() < 16 * 3) hex_line += "   ";
                      
                      ImGui::Text("%04zX  %s | %s", (i / 16) * 16, hex_line.c_str(), ascii_line.c_str());
                      hex_line = "";
                      ascii_line = "";
                  }
              }
              ImGui::EndChild();
            }
          }

          ImGui::EndTable();
        }
        ImGui::End();
    } // FIN DE LÓGICA DE PANTALLAS

    // Renderizado
    ImGui::Render();
    int display_w, display_h;
    glfwGetFramebufferSize(ventana, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.15f, 0.16f, 0.21f, 1.00f); 
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