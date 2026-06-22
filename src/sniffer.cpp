/*----- LIBRERIAS DE ENTORNO GRÁFICO -----*/
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <GLFW/glfw3.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>

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

// Estructuras para el visualizador de capas
struct CapaTraducida {
  const char* nombre;
  const char* analogia;
  string detalles_tecnicos;
  ImVec4 color;
};

struct DetallePaqueteCapas {
  CapaTraducida enlace;     // Capa 2: Ethernet
  CapaTraducida red;        // Capa 3: IP
  CapaTraducida transporte; // Capa 4: TCP / UDP
  CapaTraducida datos;      // Capa 7: Payload / Aplicación
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
string obtenerTipoIP(const string& ip);
void menuFiltrado();
void StyleColorsUmisumi();
DetallePaqueteCapas TraducirPaqueteACapas(const PaqueteInfo& pkt);
void DibujarModoCapas(const DetallePaqueteCapas& paquete);

//---------------------------------INICIO DE LA FUNCIÓN PRINCIPAL--------------------------------------------------------------------
int main()
{

  if (!glfwInit()) {
    printf("Error: No se pudo inicializar GLFW.\n");
    return 1;
  }

  const char* glsl_version = "#version 130"; 
  GLFWwindow* ventana = nullptr;

  // --- INTENTO 1: Configuración Moderna (OpenGL 3.3) ---
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
  glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE); 

  ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes", NULL, NULL);

  // --- INTENTO 2: Modo de compatibilidad para Máquina Virtual (OpenGL 3.0) ---
  if (ventana == NULL) {
    printf("Aviso: La VM no soporta OpenGL 3.3. Intentando Modo Compartibilidad (3.0)...\n");
    glfwDefaultWindowHints(); 
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glsl_version = "#version 130"; 
    ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes (Modo Compartibilidad)", NULL, NULL);
  }

  // --- INTENTO 3: Modo seguro (Dejar que el driver básico de la maquina decida) ---
  if (ventana == NULL) {
    printf("Aviso: Falló OpenGL 3.0. Intentando el perfil más básico de Windows...\n");
    glfwDefaultWindowHints();
    ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes (Modo Seguro)", NULL, NULL);
  }

  // Si ninguno de los 3 intentos funcionó
  if (ventana == NULL) {
    printf("Error Crítico: No se pudo crear la ventana en ningún modo gráfico.\n");
    glfwTerminate();
    system("pause");
    return 1;
  }

  // Identificador del sistema nativo de Windows
  HWND hwnd = glfwGetWin32Window(ventana);
  
  char ruta_exe[MAX_PATH];
  GetModuleFileNameA(NULL, ruta_exe, MAX_PATH);
  
  string ruta_carpeta = string(ruta_exe);
  size_t ultimo_slash = ruta_carpeta.find_last_of("\\/");
  if (ultimo_slash != string::npos) {
    ruta_carpeta = ruta_carpeta.substr(0, ultimo_slash + 1);
  }
  
  string ruta_icono = ruta_carpeta + "icono.ico";

  HICON hIcon = (HICON)LoadImageA(NULL, ruta_icono.c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE | LR_SHARED);
  
  if (hIcon != NULL) {
    SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
  } else {
    printf("No se pudo cargar el archivo icono.ico en la ruta: %s\n", ruta_icono.c_str());
  }

  // Inicializar el contexto final de la ventana
  glfwMakeContextCurrent(ventana);
  glfwSwapInterval(1);

  // Inicializamos el entorno de ImGui
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  (void)io;
  StyleColorsUmisumi();

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
            if (ImGui::MenuItem("Tema Personalizado")) StyleColorsUmisumi();
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
      
      ImGui::Begin("Pantalla de Inicio", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

      float windowWidth = ImGui::GetWindowSize().x;

      // Título del proyecto
      ImGui::SetCursorPosY(30.0f);
      const char *titulo = "SNIFFER - PROYECTO DE REDES";
      ImGui::SetWindowFontScale(2.5f); // Subido un poco para emparejar la estética de ayuda
      float textWidth = ImGui::CalcTextSize(titulo).x;
      ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
      ImGui::TextUnformatted(titulo);
      ImGui::SetWindowFontScale(1.0f);

      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::Spacing();

      ImGui::BeginChild("ContenidoInicio", ImVec2(0, viewportSize.y - 140.0f), false);

      // Empujamos los botones hacia el centro vertical del contenedor
      ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (viewportSize.y * 0.1f));

      // Configuramos tamaño de los botones
      float btnWidth = 300.0f;
      float btnHeight = 60.0f;

      ImGui::SetWindowFontScale(1.5f);

      // Botón para entrar al Sniffer
      ImGui::SetCursorPosX((windowWidth - btnWidth) * 0.5f);
      if (ImGui::Button("Entrar al Sniffer", ImVec2(btnWidth, btnHeight)))
      {
        estado_actual = SNIFFER;
      }
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

      ImGui::SetWindowFontScale(1.2f); // Escala para la sección de créditos

      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::Spacing();

      // Sección de nuestros creditos
      const char *label_devs = "Programa desarrollado por:";
      float devWidth = ImGui::CalcTextSize(label_devs).x;
      ImGui::SetCursorPosX((windowWidth - devWidth) * 0.5f);
      ImGui::TextUnformatted(label_devs);
      ImGui::Spacing();

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

      ImGui::EndChild();
      ImGui::SetWindowFontScale(1.0f); // Restauramos la escala

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

      float menu_offset = 20.0f; 
      
      float altoControl = 220.0f; 
      
      float espacio_restante = viewportSize.y - menu_offset - altoControl;

      float altoTabla = espacio_restante * 0.55f;
      float altoAnalisis = espacio_restante * 0.45f;

      //VENTANA DE CONTROL
      ImGui::SetNextWindowPos(ImVec2(0, menu_offset), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x, altoControl), ImGuiCond_Always);
      ImGui::Begin("Control de Sniffer", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);

      if (!captura_activa) {
          ImGui::Text("Estado: Detenido");
      } else {
          ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "Estado: Capturando..."); // Verde para resaltar
      }

      ImGui::SameLine(); 

      float controlWindowWidth = ImGui::GetWindowSize().x;
      float espaciadoBotones = ImGui::GetStyle().ItemSpacing.x;
      float margenDerecho = 15.0f;
      
      float w_volver = 90.0f;
      float w_ayuda = 90.0f;
      float w_stats = 110.0f;
      float w_export = 110.0f;

      // Empujamos los botones a la derecha en la misma línea del texto de Estado
      ImGui::SetCursorPosX(controlWindowWidth - w_volver - w_ayuda - w_stats - w_export - (espaciadoBotones * 3) - margenDerecho);

      bool esta_deshabilitado = captura_activa; 
      if (esta_deshabilitado) {
        ImGui::BeginDisabled();
      }

      if (ImGui::Button("Volver", ImVec2(w_volver, 0))) {
        estado_actual = PANTALLA_INICIO;
      }

      if (esta_deshabilitado) {
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
          ImGui::SetTooltip("Por favor, deten la captura de trafico antes de volver al menu principal.");
        }
      }

      ImGui::SameLine();
      if (ImGui::Button("Ayuda", ImVec2(w_ayuda, 0))) {
        estado_anterior = SNIFFER;
        estado_actual = VENTANA_AYUDA;
      }

      ImGui::SameLine();
      static bool mostrar_estadisticas = false; 
      if (ImGui::Button("Estadisticas", ImVec2(w_stats, 0))) {
          mostrar_estadisticas = !mostrar_estadisticas;
      }

      ImGui::SameLine();
      static bool abrir_modal_exportar = false;
      if (ImGui::Button("Exportar CSV", ImVec2(w_export, 0))) {
          abrir_modal_exportar = true;
      }

      // Separador visual antes del selector de red
      ImGui::Spacing();
      ImGui::Spacing();

      if (!captura_activa)
      {
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

      // Panel de estadísticas
      if (mostrar_estadisticas) {
          ImGui::Begin("Gráfico de Trafico", &mostrar_estadisticas, ImGuiWindowFlags_AlwaysAutoResize);
          
          map<string, int> conteo_protocolos;
          int total_paquetes = 0;

          paquetes_mutex.lock();
          total_paquetes = lista_paquetes.size();
          for (const auto& pkt : lista_paquetes) {
              conteo_protocolos[pkt.protocolo]++; 
          }
          paquetes_mutex.unlock();

          //Dibujamos la interfaz
          if (total_paquetes > 0) {
              ImGui::Text("Total de paquetes en la red: %d", total_paquetes);
              ImGui::Separator();
              ImGui::Spacing();

              // Recorremos nuestro mapa de resultados
              for (auto const& [proto, count] : conteo_protocolos) {
                  float porcentaje = (float)count / total_paquetes;
                  
                  // Texto alineado a la izquierda
                  ImGui::Text("%s:", proto.c_str());
                  
                  // Texto centrado 
                  ImGui::SameLine(120.0f); 
                  ImGui::Text("%d (%.1f%%)", count, porcentaje * 100.0f);
                  
                  // Barra a la derecha
                  ImGui::SameLine(240.0f); 
                  
                  // Usamos tu función para obtener el color del protocolo y le subimos la opacidad al 100% para la barra
                  ImVec4 color_barra = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo(proto));
                  color_barra.w = 1.0f; 
                  
                  ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color_barra);
                  
                  // Dibujamos el rectángulo de la gráfica
                  ImGui::ProgressBar(porcentaje, ImVec2(250.0f, 15.0f), "");
                  
                  ImGui::PopStyleColor();
              }
          } else {
              ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "Aun no hay trafico capturado para graficar.");
          }
          
          ImGui::End();
      }


      // iniciamos la segunda seccion grafica donde se muestra todo el trafico capturado
      ImGui::SetNextWindowPos(ImVec2(0, menu_offset + altoControl), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x, altoTabla), ImGuiCond_Always);
      ImGui::Begin("Paquetes Capturados", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);

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
            char label_id[64];
            sprintf(label_id, "%d##%p", pkt.id, &pkt);

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
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::Text("%s", obtenerTipoIP(pkt.IP_origen).c_str());
                ImGui::EndTooltip();
            }
            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%s", pkt.IP_destino.c_str());
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::Text("%s", obtenerTipoIP(pkt.IP_destino).c_str());
                ImGui::EndTooltip();
            }
            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%s", pkt.protocolo.c_str());
            if (ImGui::IsItemHovered()) {
              ImGui::BeginTooltip();
              if (pkt.protocolo == "DNS") ImGui::Text("DNS: Traduce nombres de páginas web a direcciones numéricas.");
              else if (pkt.protocolo == "HTTP") ImGui::Text("HTTP: Tráfico web normal (¡Cuidado, no está encriptado!).");
              else if (pkt.protocolo == "HTTPS") ImGui::Text("HTTPS: Tráfico web seguro y encriptado.");
              else if (pkt.protocolo == "ICMP") ImGui::Text("ICMP: Usado para pruebas de conexión como el 'Ping'.");
              else if (pkt.protocolo == "TCP") ImGui::Text("TCP: Protocolo confiable (asegura que los datos lleguen completos).");
              else if (pkt.protocolo == "UDP") ImGui::Text("UDP: Protocolo rápido pero no confiable (usado en juegos y videos).");
              else ImGui::Text("Protocolo de red.");
              ImGui::EndTooltip();
            }
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
              char label_id[64];
              sprintf(label_id, "%d##%p", pkt.id, &pkt);
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
      ImGui::SetNextWindowPos(ImVec2(0, menu_offset + altoControl + altoTabla), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x, altoAnalisis), ImGuiCond_Always);
      ImGui::Begin("Analisis del paquete", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);

      if (ImGui::BeginTable("TablaDetalles", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
      {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Analisis - Detalle del paquete", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Hexadecimal - Bytes del paquete", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        if (idPaqueteSeleccionado != -1)
        {
          PaqueteInfo* pkt_actual = nullptr;

          paquetes_mutex.lock();
          for (auto &pkt : lista_paquetes)
          {
            if (pkt.id == idPaqueteSeleccionado)
            {
              pkt_actual = &pkt;
              break;
            }
          }
          paquetes_mutex.unlock();

          if (pkt_actual != nullptr)
          {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);

            // --- BARRA DE PESTAÑAS PARA EL DESGLOSE ---
            if (ImGui::BeginTabBar("TabsAnalisisDetallado"))
            {
              if (ImGui::BeginTabItem("Árbol Técnico"))
              {
                string titulo_trama = "Trama " + to_string(pkt_actual->id);
                if (ImGui::TreeNode(titulo_trama.c_str()))
                {
                  ImGui::Text("Hora de llegada: %s", pkt_actual->tiempo_vida.c_str());
                  ImGui::Text("Longitud: %d bytes", pkt_actual->longitud);
                  ImGui::TreePop();
                }

                if (ImGui::TreeNode("Ethernet II"))
                {
                  ImGui::Text("MAC Destino: %s", pkt_actual->mac_destino.c_str());
                  ImGui::Text("MAC Origen:  %s", pkt_actual->mac_origen.c_str());
                  ImGui::TreePop();
                }

                string titulo_ip = "IPv4";
                if (ImGui::TreeNode(titulo_ip.c_str()))
                {
                  ImGui::Text("IP Origen:  %s", pkt_actual->IP_origen.c_str());
                  ImGui::Text("IP Destino: %s", pkt_actual->IP_destino.c_str());
                  ImGui::Text("Tiempo de vida (TTL): %d", pkt_actual->ttl);
                  ImGui::TreePop();
                }

                string titulo_puertos = "Protocolo de transporte (" + pkt_actual->protocolo + ")";
                if (ImGui::TreeNode(titulo_puertos.c_str()))
                {
                  ImGui::Text("Puerto Origen:  %s", pkt_actual->Puerto_origen.c_str());
                  ImGui::Text("Puerto Destino: %s", pkt_actual->Puerto_destino.c_str());
                  ImGui::TreePop();
                }

                if (pkt_actual->mostrar_dns)
                {
                  if (ImGui::TreeNode("Análisis DNS"))
                  {
                    ImGui::Text("Dominio consultado: %s", pkt_actual->nombre_dns.c_str());
                    ImGui::TreePop();
                  }
                }
                ImGui::EndTabItem();
              }

              if (ImGui::BeginTabItem("Modo Rayos X"))
              {
                DetallePaqueteCapas datos_xray = TraducirPaqueteACapas(*pkt_actual);
                DibujarModoCapas(datos_xray);
                ImGui::EndTabItem();
              }
              ImGui::EndTabBar();
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::SeparatorText("Contenido del Paquete Hexadecimal");

            ImGui::BeginChild("HexDumpRegion", ImVec2(0, 180), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);

            string hex_line;
            string ascii_line;
            for (size_t i = 0; i < pkt_actual->raw_data.size(); i++)
            {
              char hex_buf[4];
              sprintf(hex_buf, "%02X ", pkt_actual->raw_data[i]);
              hex_line += hex_buf;

              char c = pkt_actual->raw_data[i];
              ascii_line += (c >= 32 && c <= 126) ? c : '.';

              if ((i + 1) % 16 == 0 || i == pkt_actual->raw_data.size() - 1)
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

// Funcion para asignar un color a cada protocolo
ImU32 ObtenerColorProtocolo(const std::string &protocolo)
{
  // Tonos pastel muy suaves (baja opacidad al 12% para que el texto resalte)
  if (protocolo == "TCP")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.20f, 0.45f, 0.85f, 0.12f)); // Azul sutil
  if (protocolo == "UDP")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.90f, 0.50f, 0.10f, 0.12f)); // Naranja sutil
  if (protocolo == "DNS")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.25f, 0.65f, 0.35f, 0.12f)); // Verde sutil
  if (protocolo == "HTTP")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.65f, 0.30f, 0.65f, 0.12f)); // Púrpura sutil
  if (protocolo == "HTTPS")
    return ImGui::ColorConvertFloat4ToU32(ImVec4(0.85f, 0.25f, 0.25f, 0.12f)); // Rojo sutil

  return ImGui::ColorConvertFloat4ToU32(ImVec4(0.00f, 0.00f, 0.00f, 0.00f));
}

// Función para identificar si una IP es pública, privada, loopback, etc.
string obtenerTipoIP(const string& ip) {
    if (ip == "N/A" || ip.empty()) return "IP no disponible.";
    if (ip == "255.255.255.255") return "Direccion de Broadcast (Envia datos a toda la red local).";

    int o1, o2, o3, o4;
    // Extraemos los 4 octetos matematicamente para analizarlos
    if (sscanf_s(ip.c_str(), "%d.%d.%d.%d", &o1, &o2, &o3, &o4) == 4) {
        // Rangos de IP Privada
        if (o1 == 10) return "IP Privada (Clase A - Comun en redes empresariales o virtuales).";
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) return "IP Privada (Clase B - Red local).";
        if (o1 == 192 && o2 == 168) return "IP Privada (Clase C - Red local casera tipica).";
        
        // Direcciones especiales
        if (o1 == 127) return "Direccion Loopback (Trafico interno de tu propia maquina).";
        if (o1 == 169 && o2 == 254) return "Direccion Link-Local (APIPA - Asignada cuando no hay internet/DHCP).";
        if (o1 >= 224 && o1 <= 239) return "Direccion Multicast (Transmision a un grupo especifico de equipos).";

        // Si no es ninguna de las anteriores, es pública
        return "IP Publica (Servidor o equipo de Internet, visible globalmente).";
    }
    return "Direccion IP de red.";
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

void StyleColorsUmisumi(){
  ImGuiStyle& style = ImGui::GetStyle();
  ImVec4* colors = style.Colors;
  
  // --- COLOR DE LETRA EN NEGRO POR DEFECTO ---
  colors[ImGuiCol_Text]                   = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
  colors[ImGuiCol_TextDisabled]           = ImVec4(0.40f, 0.40f, 0.40f, 1.00f);
  
  // Configuración del fondo y paneles
  colors[ImGuiCol_WindowBg]               = ImVec4(0.92f, 1.00f, 0.94f, 1.00f);
  colors[ImGuiCol_ChildBg]                = ImVec4(0.85f, 0.95f, 0.88f, 0.00f); // Transparente o sutil
  colors[ImGuiCol_PopupBg]                = ImVec4(0.92f, 1.00f, 0.94f, 0.98f);
  colors[ImGuiCol_Border]                 = ImVec4(0.00f, 0.54f, 0.21f, 0.35f);
  
  // Elementos de interacción (Inputs, Combos, Checkbox)
  colors[ImGuiCol_FrameBg]                = ImVec4(0.71f, 0.97f, 0.84f, 1.00f);
  colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.26f, 0.98f, 0.60f, 0.40f);
  colors[ImGuiCol_FrameBgActive]          = ImVec4(0.26f, 0.98f, 0.65f, 0.67f);
  
  // Títulos de ventanas
  colors[ImGuiCol_TitleBg]                = ImVec4(0.42f, 0.95f, 0.59f, 1.00f);
  colors[ImGuiCol_TitleBgActive]          = ImVec4(0.15f, 0.84f, 0.37f, 1.00f);
  colors[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.42f, 0.95f, 0.59f, 0.75f);
  colors[ImGuiCol_MenuBarBg]              = ImVec4(0.00f, 0.54f, 0.21f, 1.00f);
  
  // Barras de desplazamiento
  colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.85f, 0.95f, 0.88f, 1.00f);
  colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.00f, 0.58f, 0.19f, 0.80f);
  colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.25f, 0.81f, 0.50f, 0.80f);
  colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.32f, 0.87f, 0.51f, 1.00f);
  
  // Checkmarks y Sliders
  colors[ImGuiCol_CheckMark]              = ImVec4(0.08f, 0.67f, 0.40f, 1.00f);
  colors[ImGuiCol_SliderGrab]             = ImVec4(0.26f, 0.98f, 0.56f, 0.78f);
  colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.46f, 0.80f, 0.59f, 0.60f);
  
  // Botones (Estilo verde Umisumi, sin el azul que molestaba)
  colors[ImGuiCol_Button]                 = ImVec4(0.26f, 0.98f, 0.67f, 0.57f);
  colors[ImGuiCol_ButtonHovered]          = ImVec4(0.26f, 0.98f, 0.54f, 1.00f);
  colors[ImGuiCol_ButtonActive]           = ImVec4(0.06f, 0.98f, 0.42f, 1.00f);
  
  // Cabeceras de tablas y menús desplegables
  colors[ImGuiCol_Header]                 = ImVec4(0.26f, 0.98f, 0.56f, 0.31f);
  colors[ImGuiCol_HeaderHovered]          = ImVec4(0.26f, 0.98f, 0.54f, 0.80f);
  colors[ImGuiCol_HeaderActive]           = ImVec4(0.26f, 0.98f, 0.54f, 1.00f);
  
  colors[ImGuiCol_Separator]              = ImVec4(0.00f, 0.54f, 0.21f, 0.35f);
  colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.14f, 0.80f, 0.36f, 0.78f);
  colors[ImGuiCol_SeparatorActive]        = ImVec4(0.14f, 0.80f, 0.38f, 1.00f);
  colors[ImGuiCol_ResizeGrip]             = ImVec4(0.26f, 0.98f, 0.56f, 0.20f);
  colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.26f, 0.98f, 0.52f, 0.67f);
  colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.26f, 0.98f, 0.52f, 0.95f);
  
  // Pestañas (Tabs)
  colors[ImGuiCol_Tab]                    = ImVec4(0.76f, 0.84f, 0.79f, 0.93f);
  colors[ImGuiCol_TabHovered]             = ImVec4(0.26f, 0.98f, 0.54f, 0.80f);
  colors[ImGuiCol_TabSelected]            = ImVec4(0.60f, 0.88f, 0.70f, 1.00f);
  colors[ImGuiCol_TabSelectedOverline]    = ImVec4(0.26f, 0.98f, 0.56f, 1.00f);
  colors[ImGuiCol_TabDimmed]              = ImVec4(0.92f, 0.94f, 0.93f, 0.99f);
  colors[ImGuiCol_TabDimmedSelected]      = ImVec4(0.74f, 0.91f, 0.82f, 1.00f);
  
  colors[ImGuiCol_TableHeaderBg]          = ImVec4(0.78f, 0.98f, 0.85f, 1.00f);
  colors[ImGuiCol_TableBorderStrong]      = ImVec4(0.00f, 0.54f, 0.21f, 0.35f);
  colors[ImGuiCol_TableBorderLight]       = ImVec4(0.00f, 0.54f, 0.21f, 0.15f);
  
  colors[ImGuiCol_TextLink]               = ImVec4(0.00f, 0.54f, 0.21f, 1.00f);
  colors[ImGuiCol_TextSelectedBg]         = ImVec4(0.26f, 0.98f, 0.54f, 0.35f);
  colors[ImGuiCol_DragDropTarget]         = ImVec4(0.26f, 0.98f, 0.54f, 0.95f);
  colors[ImGuiCol_NavCursor]              = ImVec4(0.26f, 0.98f, 0.50f, 0.80f);
}

// --- LOGICA DE TRADUCCIÓN METAFÓRICA (MODO RAYOS X) ---
DetallePaqueteCapas TraducirPaqueteACapas(const PaqueteInfo& pkt) {
  DetallePaqueteCapas xray;

  // 1. CAPA DE ENLACE (Ethernet - El Camión) 
  xray.enlace.nombre = "Enlace";
  xray.enlace.color = ImVec4(0.42f, 0.26f, 0.20f, 1.00f); // Tono Madera/Camión
  xray.enlace.analogia = "Es el camion fisico de mensajeria (como DHL o Estafeta) que mueve los datos desde la tarjeta de red de tu computadora hasta el modem de tu casa.";
  
  char buf_enlace[256];
  snprintf(buf_enlace, sizeof(buf_enlace), "Ethernet II | MAC Origen: %s -> MAC Destino: %s", 
          pkt.mac_origen.c_str(), pkt.mac_destino.c_str());
  xray.enlace.detalles_tecnicos = buf_enlace;

  // 2. CAPA DE RED (IP - El Sobre Postal)
  xray.red.nombre = "Red";
  xray.red.color = ImVec4(0.20f, 0.35f, 0.55f, 1.00f); // Tono Azul
  
  xray.red.analogia = "Es el sobre de papel de la carta. Tiene escrita tu direccion de casa (IP Origen) y la direccion exacta del servidor en el mundo al que quieres llegar (IP Destino).";
  char buf_red[256];
  snprintf(buf_red, sizeof(buf_red), "Protocolo: %s | IP Origen: %s -> IP Destino: %s | TTL: %d", 
          pkt.protocolo.c_str(), pkt.IP_origen.c_str(), pkt.IP_destino.c_str(), pkt.ttl);
  xray.red.detalles_tecnicos = buf_red;

  // 3. CAPA DE TRANSPORTE (TCP / UDP - Tipo de Envío)
  xray.transporte.nombre = "Transporte";
  xray.transporte.color = ImVec4(0.60f, 0.42f, 0.15f, 1.00f); // Tono Amarillo
  
  if (pkt.protocolo == "TCP" || pkt.protocolo == "HTTP" || pkt.protocolo == "HTTPS" || pkt.protocolo == "SSH / SFTP" || pkt.protocolo == "Telnet") {
    xray.transporte.analogia = "Envio Certificado (TCP): Es una entrega que exige firma de recibido. Tu computadora y el servidor aseguran que ningun fragmento de la carta se pierda o llegue roto.";
    char buf_trans[256];
    snprintf(buf_trans, sizeof(buf_trans), "TCP | Puerto Origen: %s -> Puerto Destino: %s", pkt.Puerto_origen.c_str(), pkt.Puerto_destino.c_str());
    xray.transporte.detalles_tecnicos = buf_trans;
  } else if (pkt.protocolo == "UDP" || pkt.protocolo == "DNS" || pkt.protocolo == "NTP" || pkt.protocolo == "DHCP (Server)" || pkt.protocolo == "DHCP (Client)") {
    xray.transporte.analogia = "Envio Rapido (UDP): Es como lanzar volantes desde un avion. No importa si alguno se vuela o se pierde, lo crucial es que llegue de inmediato. Ideal para juegos, streaming o consultas veloces.";
    char buf_trans[256];
    snprintf(buf_trans, sizeof(buf_trans), "UDP | Puerto Origen: %s -> Puerto Destino: %s", pkt.Puerto_origen.c_str(), pkt.Puerto_destino.c_str());
    xray.transporte.detalles_tecnicos = buf_trans;
  } else {
    xray.transporte.analogia = "Protocolo de control directo o transmision simple de datos.";
    xray.transporte.detalles_tecnicos = "Capa de Transporte Directa o Mensaje Especial.";
  }

  // 4. CAPA DE APLICACIÓN (Datos - La Carta Interna)
  xray.datos.nombre = "Datos";
  xray.datos.color = ImVec4(0.14f, 0.55f, 0.26f, 1.00f); // Tono Verde 
  xray.datos.analogia = "¡La carta que va adentro de todo! Este es el mensaje real que tus aplicaciones (como tu navegador, Discord, Minecraft o Spotify) quieren transmitir.";
  
  char buf_datos[256];
  snprintf(buf_datos, sizeof(buf_datos), "Carga Util (Payload): El paquete transporta %d Bytes de informacion pura.", pkt.longitud);
  xray.datos.detalles_tecnicos = buf_datos;

  return xray;
}

// --- INTERFAZ DE RENDERS VISUALES EN MATRIOSHKA ---
void DibujarModoCapas(const DetallePaqueteCapas& paquete) {
  ImGui::TextUnformatted("Modo Capas");
  ImGui::Separator();
  ImGui::Spacing();

  static string capa_abierta = "";
  static int ultimo_id_visto = -1;
  
  // Si cambiamos de paquete en la tabla, cerramos la inspección previa
  if (idPaqueteSeleccionado != ultimo_id_visto) {
    capa_abierta = "";
    ultimo_id_visto = idPaqueteSeleccionado;
  }

  float ancho_disponible = ImGui::GetContentRegionAvail().x;
  float alto_boton = 32.0f;
  
  // CAPA 1: ENLACE (Camión)
  ImGui::PushStyleColor(ImGuiCol_Button, paquete.enlace.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.enlace.color.x + 0.08f, paquete.enlace.color.y + 0.08f, paquete.enlace.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Enlace (El Camion de Mensajeria)", ImVec2(ancho_disponible, alto_boton))) {
    capa_abierta = "Enlace";
  }
  ImGui::PopStyleColor(2);

  // CAPA 2: RED (El Sobre)
  ImGui::Indent(20.0f); 
  ancho_disponible -= 40.0f;
  
  ImGui::PushStyleColor(ImGuiCol_Button, paquete.red.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.red.color.x + 0.08f, paquete.red.color.y + 0.08f, paquete.red.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Red (El Sobre Postal)", ImVec2(ancho_disponible, alto_boton))) {
    capa_abierta = "Red";
  }
  ImGui::PopStyleColor(2);

  // CAPA 3: TRANSPORTE (Tipo de Envío)
  ImGui::Indent(20.0f);
  ancho_disponible -= 40.0f;

  ImGui::PushStyleColor(ImGuiCol_Button, paquete.transporte.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.transporte.color.x + 0.08f, paquete.transporte.color.y + 0.08f, paquete.transporte.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Transporte (Forma de Envio)", ImVec2(ancho_disponible, alto_boton))) {
    capa_abierta = "Transporte";
  }
  ImGui::PopStyleColor(2);

  // CAPA 4: DATOS (La Carta)
  ImGui::Indent(20.0f);
  ancho_disponible -= 40.0f;

  ImGui::PushStyleColor(ImGuiCol_Button, paquete.datos.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.datos.color.x + 0.08f, paquete.datos.color.y + 0.08f, paquete.datos.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Datos (La Carta Secreta)", ImVec2(ancho_disponible, alto_boton))) {
    capa_abierta = "Datos";
  }
  ImGui::PopStyleColor(2);

  // Restauramos las sangrías de la pila gráfica de ImGui
  ImGui::Unindent(60.0f);

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  // PANEL DINÁMICO DE DETALLES
  if (!capa_abierta.empty()) {
    ImGui::BeginChild("PanelCapasExplicacion", ImVec2(0, 120), true, ImGuiWindowFlags_None);
    
    const CapaTraducida* capa_actual = nullptr;
    if (capa_abierta == "Enlace")       capa_actual = &paquete.enlace;
    else if (capa_abierta == "Red")     capa_actual = &paquete.red;
    else if (capa_abierta == "Transporte") capa_actual = &paquete.transporte;
    else if (capa_abierta == "Datos")   capa_actual = &paquete.datos;

    if (capa_actual) {
      ImGui::TextColored(ImVec4(0.00f, 0.54f, 0.21f, 1.00f), "Explicacion Sencilla:");
      ImGui::SameLine(); 
      ImGui::TextWrapped("%s", capa_actual->analogia);
      
      ImGui::Spacing();
      
      ImGui::TextColored(ImVec4(0.15f, 0.45f, 0.85f, 1.00f), "Datos Tecnicos Reales:");
      ImGui::SameLine(); 
      ImGui::TextWrapped("%s", capa_actual->detalles_tecnicos.c_str());
    }
    ImGui::EndChild();
  } else {
    ImGui::TextDisabled("Haz clic en cualquiera de los bloques de color apilados arriba para examinar su contenido.");
  }
}