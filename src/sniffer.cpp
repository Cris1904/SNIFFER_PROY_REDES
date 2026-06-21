/*----- LIBRERIAS DE ENTORNO GRÁFICO -----*/
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <GLFW/glfw3.h>

#include <thread>
#include <vector>
#include <fstream>
#include <string>
#include "captura.h"

#include <set>
#include <map>

using namespace std;

// Estructura para almacenar información detallada de los adaptadores
struct InterfazRedInfo
{
  string nombre_original; // Guarda el identificador interno de Windows (\Device\NPF_{GUID})
  string descripcion;     // Guarda la descripción cruda de Npcap (Realtek PCIe GbE...)
  string guid;            // Identificador único extraído para buscar su nombre en el registro
  string nombre_amigable; // Aquí guardaremos el nombre amigable para el usuario (Wi-Fi)
};

// ---- Estados del programa (ventanas) ----
enum EstadoPantalla
{
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
bool filtro_condicion_y = true;

const char *lista_protocolos[] = {
    "Todos", "UDP", "DNS", "DHCP (Server)", "DHCP (Client)", "TFTP", "NTP", "SNMP", "Syslog",
    "TCP", "FTP (Data)", "FTP (Control)", "SSH / SFTP", "Telnet", "SMTP", "HTTP",
    "POP3", "IMAP", "BGP", "LDAP", "HTTPS", "SMB", "SMTP (Seguro)", "LDAPS", "IMAPS"};

//------------------------------------Prototipo de funciones-------------------------------------------------------------------------
string extraerGUID(const string &nombre_npcap);
string obtenerNombreConexion(const string &guid);
string ansi_a_utf8(const string &texto_original);
string determinarTipoAdaptador(const string &descripcion);
ImU32 ObtenerColorProtocolo(const std::string &protocolo);
void menuFiltrado();

//---------------------------------INICIO DE LA FUNCIÓN PRINCIPAL--------------------------------------------------------------------
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

  ImGuiStyle& style = ImGui::GetStyle();
  
  // Redondear los bordes 
  style.WindowRounding = 8.0f;
  style.FrameRounding = 6.0f;
  style.PopupRounding = 6.0f;
  style.ChildRounding = 6.0f;
  
  // Aumentar un poco los márgenes
  style.WindowPadding = ImVec2(15, 15);
  style.FramePadding = ImVec2(8, 4);
  style.ItemSpacing = ImVec2(10, 8);

  // Paleta de colores 
  ImVec4* colors = style.Colors;
  colors[ImGuiCol_WindowBg]       = ImVec4(0.12f, 0.12f, 0.14f, 1.00f);
  colors[ImGuiCol_FrameBg]        = ImVec4(0.20f, 0.20f, 0.24f, 1.00f);
  colors[ImGuiCol_FrameBgHovered] = ImVec4(0.28f, 0.28f, 0.32f, 1.00f);
  colors[ImGuiCol_Header]         = ImVec4(0.25f, 0.45f, 0.85f, 0.80f);
  colors[ImGuiCol_Button]         = ImVec4(0.25f, 0.45f, 0.85f, 1.00f);
  colors[ImGuiCol_ButtonHovered]  = ImVec4(0.35f, 0.55f, 0.95f, 1.00f);

  // Inicializamos los backends
  ImGui_ImplGlfw_InitForOpenGL(ventana, true);
  ImGui_ImplOpenGL3_Init(glsl_version);

  // Obtenemos las interfaces disponibles y utilizamos la estructura para almacenar su información
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

      // Extraemos solo el GUID entre llaves
      info.guid = extraerGUID(info.nombre_original);

      // Solicitamos a Windows el nombre real de esta red
      string nombre_red = obtenerNombreConexion(info.guid);
      
      // Verificamos si es una máquina virtual o loopback para ponerle una etiqueta
      string etiqueta = determinarTipoAdaptador(info.descripcion);
      if (!etiqueta.empty()) {
          etiqueta += " "; // Agregamos un espacio de separación visual
      }

      // Verificamos si pudimos extraer el nombre, si si lo mostramos junto a la etiqueta y descripcion
      if (!nombre_red.empty())
      {
        info.nombre_amigable = etiqueta + nombre_red + " | " + info.descripcion;
      }
      else
      {
        // si la conexión no tiene nombre en el registro, mostramos la etiqueta y la descripcion
        info.nombre_amigable = etiqueta + "(Sin nombre) | " + info.descripcion;
      }

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
    static bool mostrar_editor_estilos = false;

    if (estado_actual == SNIFFER) {
        
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu("Apariencia y Ajustes")) {
                
                if (ImGui::BeginMenu("Temas (Colores)")) {
                    if (ImGui::MenuItem("Tema Oscuro")) ImGui::StyleColorsDark();
                    if (ImGui::MenuItem("Tema Claro")) ImGui::StyleColorsLight();
                    if (ImGui::MenuItem("Tema Clasico")) ImGui::StyleColorsClassic();
                    ImGui::EndMenu();
                }

                ImGui::Separator();

                if (ImGui::BeginMenu("Tamano de letra")) {
                    static float escala_letra = 1.0f;
                    
                    ImGui::Text("Zoom actual: %.1fx", escala_letra);
                    ImGui::Separator();

                    if (ImGui::Button("Aumentar (+)", ImVec2(150, 0))) {
                        if (escala_letra < 2.0f) escala_letra += 0.1f;
                        ImGui::GetIO().FontGlobalScale = escala_letra;
                    }
                    if (ImGui::Button("Reducir (-)", ImVec2(150, 0))) {
                        if (escala_letra > 0.6f) escala_letra -= 0.1f;
                        ImGui::GetIO().FontGlobalScale = escala_letra;
                    }
                    if (ImGui::Button("Restablecer a normal", ImVec2(150, 0))) {
                        escala_letra = 1.0f;
                        ImGui::GetIO().FontGlobalScale = 1.0f;
                    }
                    ImGui::EndMenu();
                }

                ImGui::Separator();
                
                // ¡Esta es el arma secreta para el profe!
                ImGui::Checkbox("Abrir editor avanzado de ImGui", &mostrar_editor_estilos);

                ImGui::EndMenu();
            }
            ImGui::EndMainMenuBar();
        }

        // Si la palomita está marcada, ImGui dibuja su ventana de configuración 
        if (mostrar_editor_estilos) {
            ImGui::Begin("Editor de Estilos", &mostrar_editor_estilos);
            ImGui::ShowStyleEditor();
            ImGui::End();
        }
        
    }
    // Obtener el tamaño actual de la ventana
    ImVec2 viewportSize = ImGui::GetIO().DisplaySize;

    // Definimos la logica de las ventanas
    if (estado_actual == PANTALLA_INICIO)
    {
      // --- PANTALLA DE INICIO ---
      ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
      ImGui::SetNextWindowSize(viewportSize, ImGuiCond_Always);
      ImGui::Begin("Pantalla de Inicio", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBackground);

      float windowWidth = ImGui::GetWindowSize().x;

      // Título del proyecto
      ImGui::SetCursorPosY(20.0f);
      const char *titulo = "SNIFFER - PROYECTO DE REDES";
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
      if (ImGui::Button("Entrar al Sniffer", ImVec2(btnWidth, btnHeight)))
      {
        estado_actual = SNIFFER;
      }
      ImGui::PopStyleColor();
      ImGui::Spacing();
      ImGui::Spacing();

      // Botón para Menú de Ayuda
      ImGui::SetCursorPosX((windowWidth - btnWidth) * 0.5f);
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.4f, 0.4f, 0.4f, 1.0f)); // Gris
      if (ImGui::Button("Menu de Ayuda", ImVec2(btnWidth, btnHeight)))
      {
        estado_anterior = PANTALLA_INICIO; // Guardamos que venimos del inicio
        estado_actual = VENTANA_AYUDA;
      }
      ImGui::PopStyleColor();

      ImGui::SetWindowFontScale(1.0f); // Restauramos la escala de la fuente

      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::Spacing();

      // Sección de nuestros creditos
      const char *label_devs = "Programa desarrollado por:";
      float devWidth = ImGui::CalcTextSize(label_devs).x;
      ImGui::SetCursorPosX((windowWidth - devWidth) * 0.5f);
      ImGui::TextUnformatted(label_devs);

      const char *dev1 = "- Tania Jaquelin Lopez Acevedo";
      const char *dev2 = "- Antonio Duron Mendoza";
      const char *dev3 = "- Ulises Raygoza Castaneda";
      const char *dev4 = "- Cristian de Jesus Vazquez Delgado";
      const char *dev5 = "Correo de contacto: equipoumisumi4321@gmail.com";

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
      ImGui::Spacing();
      ImGui::Spacing();
      float dev5Width = ImGui::CalcTextSize(dev5).x;
      ImGui::SetCursorPosX((windowWidth - dev5Width) * 0.5f);
      ImGui::TextUnformatted(dev5);

      ImGui::End();
    }
    else if (estado_actual == VENTANA_AYUDA)
    {
      // --- PANTALLA DE AYUDA ---
      ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
      ImGui::SetNextWindowSize(viewportSize, ImGuiCond_Always);
      ImGui::Begin("Ventana de Ayuda", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

      float windowWidthAyuda = ImGui::GetWindowSize().x;

      // Título del menú de ayuda
      ImGui::SetCursorPosY(20.0f);
      const char *tituloAyuda = "MENU DE AYUDA";
      ImGui::SetWindowFontScale(2.5f);
      float helpTextWidth = ImGui::CalcTextSize(tituloAyuda).x;
      ImGui::SetCursorPosX((windowWidthAyuda - helpTextWidth) * 0.5f);
      ImGui::TextUnformatted(tituloAyuda);

      ImGui::SetWindowFontScale(1.4f);

      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::Spacing();

      // Contenedor interno para las instrucciones
      ImGui::BeginChild("Instrucciones", ImVec2(0, viewportSize.y - 140.0f), false);

      ImGui::TextWrapped("Conoce tu Sniffer. Este programa te permite ver y analizar el tráfico de red. A continuación te explicamos cómo funciona cada sección para que aproveches al maximo sus funciones:");
      ImGui::Spacing();
      ImGui::Spacing();

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
      ImGui::Text("\n\nPara mas información, comunicate con los desarrolladores, mandando un correo a la cuenta gmail que aparece en la parte inferior del menu principal");
      
      ImGui::EndChild();

      ImGui::SetWindowFontScale(1.5f);

      // Botón "Volver" centrado y hasta abajo
      float btnVolverWidth = 200.0f;
      float btnVolverHeight = 50.0f;

      ImGui::SetCursorPosY(viewportSize.y - btnVolverHeight - 20.0f);
      ImGui::SetCursorPosX((windowWidthAyuda - btnVolverWidth) * 0.5f);

      if (ImGui::Button("Volver", ImVec2(btnVolverWidth, btnVolverHeight)))
      {
        estado_actual = estado_anterior;
      }

      ImGui::SetWindowFontScale(1.0f);

      ImGui::End();
    }
    else if (estado_actual == SNIFFER)
    {
      // --- PANTALLA PRINCIPAL DEL SNIFFER ---
      float menu_offset = 25.0f; 
      float padding = 10.0f;    

      // El panel de control tiene altura fija para evitar espacios inútiles
      float altoControl = 180.0f; 
      
      // Calculamos cuánto espacio útil queda en la pantalla sin pasarnos del límite
      float espacio_restante = viewportSize.y - menu_offset - (padding * 4) - altoControl;
      
      // Repartimos lo que sobra: 60% a la lista de paquetes y 40% al análisis
      float altoTabla = espacio_restante * 0.6f;
      float altoAnalisis = espacio_restante * 0.4f;

      // Configuramos la posición y tamaño de la ventana de control, teniendo en cuenta el nuevo offset por el menú y el padding
      ImGui::SetNextWindowPos(ImVec2(padding, menu_offset + padding), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoControl), ImGuiCond_Always);
      ImGui::Begin("Control de Sniffer", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

      float controlWindowWidth = ImGui::GetWindowSize().x;
      float btnVolverWidth = 100.0f;
      float btnAyudaWidth = 100.0f;
      float btnExportarWidth = 120.0f; 
      float espaciadoBotones = ImGui::GetStyle().ItemSpacing.x;
      float margenDerecho = 15.0f;

      ImGui::SetCursorPosX(controlWindowWidth - btnVolverWidth - btnAyudaWidth - btnExportarWidth - (espaciadoBotones * 2) - margenDerecho);

      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.5f, 0.9f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.1f, 0.3f, 0.7f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.0f, 0.2f, 0.5f, 1.0f));

      // Habilitar o deshabilitar el boton "volver" para evitar cierres accidentales durante la captura
      if (captura_activa)
      {
        ImGui::BeginDisabled();
      }

      if (ImGui::Button("Volver", ImVec2(btnVolverWidth, 0)))
      {
        estado_actual = PANTALLA_INICIO;
      }

      if (captura_activa)
      {
        ImGui::EndDisabled();

        // Mensaje flotante indicando por qué está deshabilitado
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        {
          ImGui::SetTooltip("Por favor, deten la captura de trafico antes de volver al menu principal.");
        }
      }

      ImGui::SameLine();
      if (ImGui::Button("Ayuda", ImVec2(btnAyudaWidth, 0)))
      {
        estado_anterior = SNIFFER;
        estado_actual = VENTANA_AYUDA;
      }

      ImGui::SameLine();
      static bool abrir_modal_exportar = false;
      if (ImGui::Button("Exportar CSV", ImVec2(btnExportarWidth, 0))) {
          abrir_modal_exportar = true;
      }

      ImGui::PopStyleColor(3);

      ImGui::Spacing();
      ImGui::Separator();
      ImGui::Spacing();

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
      if (abrir_modal_exportar) {
          ImGui::OpenPopup("Exportar a CSV");
          abrir_modal_exportar = false;
      }

      static bool col_id = true, col_tiempo = true, col_longitud = true;
      static bool col_ip_o = true, col_ip_d = true, col_proto = true;
      static bool col_puerto_o = true, col_puerto_d = true;

      if (ImGui::BeginPopupModal("Exportar a CSV", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
          ImGui::Text("Selecciona las columnas a exportar:");
          ImGui::Separator();
          ImGui::Spacing();
          ImGui::Checkbox("Numero de paquete", &col_id);
          ImGui::Checkbox("Tiempo de vida", &col_tiempo);
          ImGui::Checkbox("Longitud (Bytes)", &col_longitud);
          ImGui::Checkbox("IP Origen", &col_ip_o);
          ImGui::Checkbox("IP Destino", &col_ip_d);
          ImGui::Checkbox("Protocolo", &col_proto);
          ImGui::Checkbox("Puerto Origen", &col_puerto_o);
          ImGui::Checkbox("Puerto Destino", &col_puerto_d);
          ImGui::Separator();
          ImGui::Spacing();
          if (ImGui::Button("Exportar", ImVec2(120, 0))) {
              ofstream archivo("captura_trafico.csv");
              if (archivo.is_open()) {
                  string cabecera = "";
                  if (col_id) cabecera += "Numero,";
                  if (col_tiempo) cabecera += "Tiempo,";
                  if (col_longitud) cabecera += "Longitud,";
                  if (col_ip_o) cabecera += "IP Origen,";
                  if (col_ip_d) cabecera += "IP Destino,";
                  if (col_proto) cabecera += "Protocolo,";
                  if (col_puerto_o) cabecera += "Puerto Origen,";
                  if (col_puerto_d) cabecera += "Puerto Destino,";
                  
                  if (!cabecera.empty()) cabecera.pop_back();
                  archivo << cabecera << "\n";

                  //Extraemos los datos paquete por paquete
                  paquetes_mutex.lock(); // Bloqueamos para leer seguro
                  for (const auto& pkt : lista_paquetes) {
                      string linea = "";
                      if (col_id) linea += to_string(pkt.id) + ",";
                      if (col_tiempo) linea += pkt.tiempo_vida + ",";
                      if (col_longitud) linea += to_string(pkt.longitud) + ",";
                      if (col_ip_o) linea += pkt.IP_origen + ",";
                      if (col_ip_d) linea += pkt.IP_destino + ",";
                      if (col_proto) linea += pkt.protocolo + ",";
                      if (col_puerto_o) linea += pkt.Puerto_origen + ",";
                      if (col_puerto_d) linea += pkt.Puerto_destino + ",";
                      
                      if (!linea.empty()) linea.pop_back(); // Quitamos la última coma
                      archivo << linea << "\n";
                  }
                  paquetes_mutex.unlock();
                  
                  archivo.close();
              }
              ImGui::CloseCurrentPopup();
          }

          ImGui::SameLine(); //botón cancelar a un lado

          if (ImGui::Button("Cancelar", ImVec2(120, 0))) {
              ImGui::CloseCurrentPopup();
          }
          ImGui::EndPopup();
      }
      ImGui::End();

      // iniciamos la segunda seccion grafica donde se muestra todo el trafico capturado
      ImGui::SetNextWindowPos(ImVec2(padding, menu_offset + (padding * 2) + altoControl), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoTabla), ImGuiCond_Always);
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
          for (auto &pkt : lista_paquetes)
          {
            bool mostrar = false;
            
            if (filtro_condicion_y) {
                //Todas las casillas que no estén vacías deben coincidir
                mostrar = ((ip_o[0] == '\0' || strcmp(ip_o, pkt.IP_origen.c_str()) == 0) &&
                           (ip_d[0] == '\0' || strcmp(ip_d, pkt.IP_destino.c_str()) == 0) &&
                           (proto[0] == '\0' || strcmp(proto, pkt.protocolo.c_str()) == 0) &&
                           (puerto_d[0] == '\0' || strcmp(puerto_d, pkt.Puerto_destino.c_str()) == 0));
            } else {
                //Con que una sola casilla coincida, mostramos el paquete
                bool coincide_ip_o = (ip_o[0] != '\0' && strcmp(ip_o, pkt.IP_origen.c_str()) == 0);
                bool coincide_ip_d = (ip_d[0] != '\0' && strcmp(ip_d, pkt.IP_destino.c_str()) == 0);
                bool coincide_proto = (proto[0] != '\0' && strcmp(proto, pkt.protocolo.c_str()) == 0);
                bool coincide_puerto = (puerto_d[0] != '\0' && strcmp(puerto_d, pkt.Puerto_destino.c_str()) == 0);
                
                mostrar = (coincide_ip_o || coincide_ip_d || coincide_proto || coincide_puerto);
            }

            if (mostrar) 
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
      ImGui::SetNextWindowPos(ImVec2(padding, menu_offset + (padding * 3) + altoControl + altoTabla), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x - (padding * 2), altoAnalisis), ImGuiCond_Always);
      ImGui::Begin("Analisis del paquete", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

      if (ImGui::BeginTable("TablaDetalles", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
      {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Detalles del paquete", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableSetupColumn("Bytes del paquete");
        ImGui::TableHeadersRow();

        if (idPaqueteSeleccionado != -1)
        {
          PaqueteInfo paquete_actual = {0, "", 0, "", "", "", "", "", 0, "", "", nullptr, 0};
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
            if (ImGui::TreeNode(titulo_trama.c_str()))
            {
              ImGui::Text("Hora de llegada: %s", paquete_actual.tiempo_vida.c_str());
              ImGui::Text("Longitud: %d bytes", paquete_actual.longitud);
              ImGui::TreePop();
            }

            if (ImGui::TreeNode("Ethernet II"))
            {
              ImGui::Text("MAC Destino: %s", paquete_actual.mac_destino.c_str());
              ImGui::Text("MAC Origen:  %s", paquete_actual.mac_origen.c_str());
              ImGui::TreePop();
            }

            string titulo_ip = "IPv4";
            if (ImGui::TreeNode(titulo_ip.c_str()))
            {
              ImGui::Text("IP Origen:  %s", paquete_actual.IP_origen.c_str());
              ImGui::Text("IP Destino: %s", paquete_actual.IP_destino.c_str());
              ImGui::Text("Tiempo de vida (TTL): %d", paquete_actual.ttl);
              ImGui::TreePop();
            }

            string titulo_puertos = "Protocolo de transporte (" + paquete_actual.protocolo + ")";
            if (ImGui::TreeNode(titulo_puertos.c_str()))
            {
              ImGui::Text("Puerto Origen:  %s", paquete_actual.Puerto_origen.c_str());
              ImGui::Text("Puerto Destino: %s", paquete_actual.Puerto_destino.c_str());
              ImGui::TreePop();
            }

            if (paquete_actual.mostrar_dns)
            {
              if (ImGui::TreeNode("Análisis DNS"))
              {
                ImGui::Text("Dominio consultado: %s", paquete_actual.nombre_dns.c_str());
                ImGui::TreePop();
              }
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::SeparatorText("Contenido del Paquete Hexadecimal");

            ImGui::BeginChild("HexDumpRegion", ImVec2(0, 180), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);

            string hex_line;
            string ascii_line;
            for (size_t i = 0; i < paquete_actual.raw_data.size(); i++)
            {
              char hex_buf[4];
              sprintf(hex_buf, "%02X ", paquete_actual.raw_data[i]);
              hex_line += hex_buf;

              char c = paquete_actual.raw_data[i];
              ascii_line += (c >= 32 && c <= 126) ? c : '.';

              if ((i + 1) % 16 == 0 || i == paquete_actual.raw_data.size() - 1)
              {
                while (hex_line.length() < 16 * 3)
                  hex_line += "   ";

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

//---------------------------------Implementacion de funciones-----------------------------------------------------------------------

//--Función para extraer unicamente el GUID de la cadena que nos devuelve Npcap------------------------------------
string extraerGUID(const string &nombre_npcap)
{
  size_t pos = nombre_npcap.find("{");
  if (pos != string::npos)
  {
    return nombre_npcap.substr(pos);
  }
  return "";
}

//--Funcion para leer el "Registro de Windows" y obtener el nombre de la red ("Wi-Fi", "Ethernet") usando el GUID--
string obtenerNombreConexion(const string &guid)
{
  if (guid.empty())
    return "";

  // Ruta estandar del registro de Windows donde se guardan las conexiones de red
  string subkey = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + guid + "\\Connection";
  HKEY hKey;

  // Intentar abrir la llave en el registro en modo lectura
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
  {
    char nombreBuffer[256];
    DWORD bufferSize = sizeof(nombreBuffer);

    // Extraer el valor "Name"
    if (RegQueryValueExA(hKey, "Name", NULL, NULL, (LPBYTE)nombreBuffer, &bufferSize) == ERROR_SUCCESS)
    {
      RegCloseKey(hKey);
      // Convertimos el texto a UTF-8 antes de devolverlo
      return ansi_a_utf8(string(nombreBuffer));
    }
    RegCloseKey(hKey);
  }
  return ""; // Si falla o no existe, devolvemos una cadena vacia
}

//-------Funcion auxiliar para convertir texto de Windows (ANSI) a UTF-8 (ImGui para mostrar acentos y ñ)---------
string ansi_a_utf8(const string &texto_original)
{
  // Verificamos cadena vacia
  if (texto_original.empty())
  {
    return "";
  }

  //De ANSI a WideChar (UTF-16)

  // calculamos cuanto espacio necesitamos para el texto intermedio
  int tamano_utf16 = MultiByteToWideChar(CP_ACP, 0, &texto_original[0], (int)texto_original.size(), NULL, 0);
  // creamos una variable temporal para guardar el texto intermedio de Windows
  wstring texto_intermedio(tamano_utf16, 0);
  // hacemos la primera traduccion
  MultiByteToWideChar(CP_ACP, 0, &texto_original[0], (int)texto_original.size(), &texto_intermedio[0], tamano_utf16);

  // De WideChar (UTF-16) a (UTF-8)

  // calculamos cuanto espacio necesitamos para el texto final
  int tamano_utf8 = WideCharToMultiByte(CP_UTF8, 0, &texto_intermedio[0], (int)texto_intermedio.size(), NULL, 0, NULL, NULL);
  // creamos la variable que guardara el texto final ya traducido
  string texto_traducido(tamano_utf8, 0);
  // hacemos la ultima traducción (al formato UTF-8 que lee ImGui)
  WideCharToMultiByte(CP_UTF8, 0, &texto_intermedio[0], (int)texto_intermedio.size(), &texto_traducido[0], tamano_utf8, NULL, NULL);

  return texto_traducido;
}

//-------Funcion para identificar si el adaptador es de una maquina virtual o loopback---------
string determinarTipoAdaptador(const string &descripcion)
{
  string desc_lower = descripcion;
  // Convertimos toda la descripcion a minusculas para buscar las palabras clave mas facil
  for (char &c : desc_lower) {
      c = tolower(c);
  }

  if (desc_lower.find("virtualbox") != string::npos) return "[VirtualBox]";
  if (desc_lower.find("vmware") != string::npos) return "[VMware]";
  if (desc_lower.find("loopback") != string::npos) return "[Loopback]";
  if (desc_lower.find("virtual") != string::npos) return "[Virtual]";
  
  return ""; // No agregamos etiqueta extra si parece ser un adaptador físico normal
}

//----------------------------------------------------------------------------------------------------------------
ImU32 ObtenerColorProtocolo(const std::string &protocolo)
{
  if (protocolo == "TCP")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.2f, 0.5f, 0.9f, 0.25f)); // Azul
  if (protocolo == "UDP")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.9f, 0.6f, 0.1f, 0.25f)); // Naranja
  if (protocolo == "DNS")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.3f, 0.8f, 0.4f, 0.25f)); // Verde
  if (protocolo == "HTTP")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.8f, 0.3f, 0.8f, 0.25f)); // Púrpura
  if (protocolo == "HTTPS")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.9f, 0.2f, 0.2f, 0.25f)); // Rojo

  return ImGui::ColorConvertFloat4ToU32(ImVec4(0.3f, 0.3f, 0.3f, 0.2f));
}

//----------------Menu de filtrado -------------------------------------------------------------------------------
void menuFiltrado()
{
  // Se guardaran en un set para evitar repetidas
  set<string> ips_origen_unicas;
  set<string> ips_destino_unicas;
  set<string> puertos_origen;
  set<string> puertos_destino;

  // Bloqueamos para extraer sin errores de escritura
  paquetes_mutex.lock();
  for (const auto &pkt : lista_paquetes)
  {
    if (!pkt.IP_origen.empty())
      ips_origen_unicas.insert(pkt.IP_origen);
    if (!pkt.IP_destino.empty())
      ips_destino_unicas.insert(pkt.IP_destino);
    if (!pkt.Puerto_origen.empty())
      puertos_origen.insert(pkt.Puerto_origen);
    if (!pkt.Puerto_destino.empty())
      puertos_destino.insert(pkt.Puerto_destino);
  }
  paquetes_mutex.unlock();

  ImGui::Text("Filtrado de paquetes");
  ImGui::SameLine();
  
  if (filtro_condicion_y) {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.6f, 0.2f, 1.0f)); 
      if (ImGui::Button("Todos los filtros")) filtro_condicion_y = false;
  } else {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.4f, 0.0f, 1.0f)); 
      if (ImGui::Button("Cualquiera de los filtros")) filtro_condicion_y = true;
  }
  ImGui::PopStyleColor();
  if (ImGui::IsItemHovered()) {
      ImGui::BeginTooltip();
      if (filtro_condicion_y) {
          ImGui::TextUnformatted("Filtro estricto:\nSolo se muestran los paquetes que tengan\nel protocolo, las IPs y los puertos que escribiste.");
      } else {
          ImGui::TextUnformatted("Filtro flexible:\nSe muestran todos los paquetes que compartan\nal menos uno de los datos que escribiste.");
      }
      ImGui::EndTooltip();
  }
  ImGui::Text("IP Origen:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(150);

  // Si la variable global 'ip_o' está vacía, mostramos "Todas"
  const char *ip_ori;
  if (ip_o[0] == '\0')
  {
    ip_ori = "Todas";
  }
  else
  {
    ip_ori = ip_o;
  }

  if (ImGui::BeginCombo("##combo_ip_o", ip_ori))
  {
    // Opción por defecto para limpiar el filtro
    bool o_todos_sel = (ip_o[0] == '\0');
    if (ImGui::Selectable("Todas", o_todos_sel))
    {
      ip_o[0] = '\0';
    }

    // Listamos las IPs reales que han llegado
    for (const auto &ip : ips_origen_unicas)
    {
      bool esta_sel = (strcmp(ip_o, ip.c_str()) == 0);
      if (ImGui::Selectable(ip.c_str(), esta_sel))
      {
        snprintf(ip_o, sizeof(ip_o), "%s", ip.c_str());
      }
    }
    ImGui::EndCombo();
  }

  ImGui::SameLine();
  ImGui::Text("IP Destino:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(150);

  const char *ip_des;
  if (ip_d[0] == '\0')
  {
    ip_des = "Todas";
  }
  else
  {
    ip_des = ip_d;
  }

  if (ImGui::BeginCombo("##combo_ip_d", ip_des))
  {
    // Opción por defecto para limpiar el filtro
    bool d_todos_sel = (ip_d[0] == '\0');
    if (ImGui::Selectable("Todas", d_todos_sel))
    {
      ip_d[0] = '\0';
    }

    // Listamos las IPs reales que han llegado
    for (const auto &ip : ips_destino_unicas)
    {
      bool esta_sel = (strcmp(ip_d, ip.c_str()) == 0);
      if (ImGui::Selectable(ip.c_str(), esta_sel))
      {
        snprintf(ip_d, sizeof(ip_d), "%s", ip.c_str());
      }
    }
    ImGui::EndCombo();
  }

  ImGui::SameLine();
  ImGui::Text("Protocolo:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(140);
  if (ImGui::BeginCombo("##proto_combo", lista_protocolos[protocolo_combo_idx]))
  {
    for (int n = 0; n < IM_ARRAYSIZE(lista_protocolos); n++)
    {
      const bool esta_seleccionado = (protocolo_combo_idx == n);
      if (ImGui::Selectable(lista_protocolos[n], esta_seleccionado))
      {
        protocolo_combo_idx = n;

        // Si selecciona "Todos", vaciamos la cadena para desactivar el filtro de protocolo
        if (n == 0)
        {
          proto[0] = '\0';
        }
        else
        {
          // Copiamos el nombre del protocolo seleccionado a la variable global 'proto'
          snprintf(proto, sizeof(proto), "%s", lista_protocolos[n]);
        }
      }

      if (esta_seleccionado)
      {
        ImGui::SetItemDefaultFocus();
      }
    }
    ImGui::EndCombo();
  }

  ImGui::SameLine();
  ImGui::Text("Puerto destino:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(80);

  const char *puerto_des;
  if (puerto_d[0] == '\0')
  {
    puerto_des = "Todos";
  }
  else
  {
    puerto_des = puerto_d;
  }

  if (ImGui::BeginCombo("##combo_puertos_des", puerto_des))
  {
    // Opción por defecto para limpiar el filtro
    bool p_todos_sel = (puerto_d[0] == '\0');
    if (ImGui::Selectable("Todos", p_todos_sel))
    {
      puerto_d[0] = '\0';
    }

    for (const auto &puerto : puertos_destino)
    {
      bool esta_sel = (strcmp(puerto_d, puerto.c_str()) == 0);
      if (ImGui::Selectable(puerto.c_str(), esta_sel))
      {
        snprintf(puerto_d, sizeof(puerto_d), "%s", puerto.c_str());
      }
    }
    ImGui::EndCombo();
  }
}