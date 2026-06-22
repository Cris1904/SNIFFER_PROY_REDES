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

// Estructuras para la parte grafica de los paquetes
struct EsferaViajera
{
  float progreso;      // De 0.0 (PC) a 1.0 (Nube)
  float velocidad;     // Multiplicador de velocidad por segundo
  ImVec4 color;        // Color representativo del protocolo
  bool deUsuarioANube; // true = PC -> Nube (Salida), false = Nube -> PC (Entrada)
};

std::vector<EsferaViajera> esferas_activas;
int ultimo_id_procesado_esfera = -1; // Para saber qué paquetes ya se animaron

// Estructura para almacenar información detallada de los adaptadores
struct InterfazRedInfo
{
  string nombre_original; // Guarda el identificador interno de Windows (\Device\NPF_{GUID})
  string descripcion;     // Guarda la descripción cruda de Npcap (Realtek PCIe GbE...)
  string guid;            // Identificador único extraído para buscar su nombre en el registro
  string nombre_amigable; // Aquí guardaremos el nombre amigable para el usuario (Wi-Fi)
};

// Estructuras para el visualizador de capas
struct CapaTraducida
{
  const char *nombre;
  const char *analogia;
  string detalles_tecnicos;
  ImVec4 color;
};

struct DetallePaqueteCapas
{
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
char puerto_o[64] = "";
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
string obtenerTipoIP(const string &ip);
void menuFiltrado();
void StyleColorsUmisumi();
DetallePaqueteCapas TraducirPaqueteACapas(const PaqueteInfo &pkt);
void DibujarModoCapas(const DetallePaqueteCapas &paquete);

//---------------------------------INICIO DE LA FUNCIÓN PRINCIPAL--------------------------------------------------------------------
int main()
{

  if (!glfwInit())
  {
    printf("Error: No se pudo inicializar GLFW.\n");
    return 1;
  }

  const char *glsl_version = "#version 130";
  GLFWwindow *ventana = nullptr;

  // --- INTENTO 1: Configuración Moderna (OpenGL 3.3) ---
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
  glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

  ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes", NULL, NULL);

  // --- INTENTO 2: Modo de compatibilidad para Máquina Virtual (OpenGL 3.0) ---
  if (ventana == NULL)
  {
    printf("Aviso: La VM no soporta OpenGL 3.3. Intentando Modo Compartibilidad (3.0)...\n");
    glfwDefaultWindowHints();
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glsl_version = "#version 130";
    ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes (Modo Compartibilidad)", NULL, NULL);
  }

  // --- INTENTO 3: Modo seguro (Dejar que el driver básico de la maquina decida) ---
  if (ventana == NULL)
  {
    printf("Aviso: Falló OpenGL 3.0. Intentando el perfil más básico de Windows...\n");
    glfwDefaultWindowHints();
    ventana = glfwCreateWindow(1280, 720, "Sniffer - Proyecto de Redes (Modo Seguro)", NULL, NULL);
  }

  // Si ninguno de los 3 intentos funcionó
  if (ventana == NULL)
  {
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
  if (ultimo_slash != string::npos)
  {
    ruta_carpeta = ruta_carpeta.substr(0, ultimo_slash + 1);
  }

  string ruta_icono = ruta_carpeta + "icono.ico";

  HICON hIcon = (HICON)LoadImageA(NULL, ruta_icono.c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE | LR_SHARED);

  if (hIcon != NULL)
  {
    SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
  }
  else
  {
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

  ImGuiStyle &style = ImGui::GetStyle();

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
      if (!etiqueta.empty())
      {
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

    if (estado_actual == SNIFFER)
    {

      if (ImGui::BeginMainMenuBar())
      {
        if (ImGui::BeginMenu("Apariencia y Ajustes"))
        {

          if (ImGui::BeginMenu("Temas (Colores)"))
          {
            if (ImGui::MenuItem("Tema Personalizado"))
              StyleColorsUmisumi();
            if (ImGui::MenuItem("Tema Oscuro"))
              ImGui::StyleColorsDark();
            if (ImGui::MenuItem("Tema Claro"))
              ImGui::StyleColorsLight();
            if (ImGui::MenuItem("Tema Clasico"))
              ImGui::StyleColorsClassic();
            ImGui::EndMenu();
          }

          ImGui::Separator();

          if (ImGui::BeginMenu("Tamano de letra"))
          {
            static float escala_letra = 1.0f;

            ImGui::Text("Zoom actual: %.1fx", escala_letra);
            ImGui::Separator();

            if (ImGui::Button("Aumentar (+)", ImVec2(150, 0)))
            {
              if (escala_letra < 2.0f)
                escala_letra += 0.1f;
              ImGui::GetIO().FontGlobalScale = escala_letra;
            }
            if (ImGui::Button("Reducir (-)", ImVec2(150, 0)))
            {
              if (escala_letra > 0.6f)
                escala_letra -= 0.1f;
              ImGui::GetIO().FontGlobalScale = escala_letra;
            }
            if (ImGui::Button("Restablecer a normal", ImVec2(150, 0)))
            {
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
      if (mostrar_editor_estilos)
      {
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
      // Forzar a que ocupe toda la pantalla de forma limpia
      ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
      ImGui::SetNextWindowSize(viewportSize, ImGuiCond_Always);

      ImGui::Begin("Manual de Usuario & Conceptos de Red", NULL,
                   ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_MenuBar);

      // Barra de menú superior para salir rápido de la ayuda
      if (ImGui::BeginMenuBar())
      {
        if (ImGui::MenuItem("<< Volver al Sniffer"))
        {
          estado_actual = SNIFFER; // Regresa directamente al panel de monitoreo activo
        }
        if (ImGui::MenuItem("<< Volver al Inicio"))
        {
          estado_actual = PANTALLA_INICIO; // Regresa a la selección de interfaces
        }
        ImGui::EndMenuBar();
      }

      ImGui::TextColored(ImVec4(0.14f, 0.80f, 0.36f, 1.0f), "GUÍA COMPLETA DEL ANALIZADOR DE PROTOCOLOS");
      ImGui::Text("Aprende cómo interpretar los datos capturados y el funcionamiento de la aplicación.");
      ImGui::Separator();
      ImGui::Spacing();

      // --- SISTEMA DE PESTAÑAS PARA ORGANIZAR LA AYUDA ---
      if (ImGui::BeginTabBar("TabsAyuda"))
      {
        // PESTAÑA 1: ¿CÓMO USAR EL PROGRAMA?
        if (ImGui::BeginTabItem("Uso del Sniffer"))
        {
          ImGui::TextColored(ImVec4(0.0f, 0.75f, 1.0f, 1.0f), "Guía de Operación y Arquitectura del Sistema:");
          ImGui::Spacing();

          ImGui::BulletText("1. Panel de Control (Superior): Elige tu tarjeta de red activa y controla la captura en tiempo real con hilos.");
          ImGui::BulletText("2. Botón de inicio/parada: Inicia o detiene la captura de paquetes en tiempo real.");
          ImGui::BulletText("3. Filtros: Configura reglas lógicas (AND/OR) y selecciona protocolos específicos para filtrar la captura.");
          ImGui::BulletText("4. Botón de ayuda: Abre esta ventana de ayuda con instrucciones y diagramas explicativos.");
          ImGui::BulletText("5. Botón de estado: Muestra el estado actual de la captura y el número de paquetes capturados.");
          ImGui::BulletText("6. Botón de exportar: Guarda los paquetes capturados en un archivo .csv o .xlsx para análisis posterior.");
          ImGui::BulletText("7. Monitoreo (Central): Examina la tabla con códigos de colores por protocolo y haz clic en una fila para congelarla.");
          ImGui::BulletText("8. Análisis (Inferior): Desglosa la trama con el Árbol Técnico, el Modo Rayos X (analogías) o inspecciona los bytes en el Hex Dump.");

          ImGui::Spacing();

          ImGui::EndTabItem();
        }

        // PESTAÑA 2: DICCIONARIO DE PROTOCOLOS (Sincronizado con tus colores reales)
        if (ImGui::BeginTabItem("Códigos de Colores y Protocolos"))
        {
          ImGui::Text("Este sniffer clasifica los paquetes por color para facilitar su análisis visual rápido:");
          ImGui::Spacing();

          // Usamos una tabla de ImGui para alinear perfectamente los nombres, colores y descripciones
          if (ImGui::BeginTable("TablaDiccionarioProtocolos", 2, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingStretchProp))
          {
            ImGui::TableSetupColumn("Protocolo", ImGuiTableColumnFlags_WidthFixed, 250.0f);
            ImGui::TableSetupColumn("Descripción y Caso de Uso");

            // --- FILA 1: TCP ---
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            // Extraemos el color exacto de tu función, pero forzamos opacidad 1.0f para que el cuadro indicador se note claro
            ImVec4 color_tcp = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo("TCP"));
            color_tcp.w = 1.0f;
            ImGui::TextColored(color_tcp, "[■] TCP (Transmission Control)");

            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("Protocolo orientado a conexión. Es confiable, maneja control de flujo y asegura que los datos lleguen sin pérdidas ni desorden.");
            ImGui::Separator();

            // --- FILA 2: UDP ---
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImVec4 color_udp = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo("UDP"));
            color_udp.w = 1.0f;
            ImGui::TextColored(color_udp, "[■] UDP (User Datagram)");

            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("Protocolo ligero no orientado a conexión. Ultra veloz al no verificar errores ni retransmitir. Ideal para flujos que toleran pérdidas.");
            ImGui::Separator();

            // --- FILA 3: DNS ---
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImVec4 color_dns = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo("DNS"));
            color_dns.w = 1.0f;
            ImGui::TextColored(color_dns, "[■] DNS (Domain Name System)");

            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("El directorio de Internet. Traduce nombres de dominio legibles (como google.com) a las direcciones IP numéricas que los routers entienden.");
            ImGui::Separator();

            // --- FILA 4: HTTP ---
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImVec4 color_http = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo("HTTP"));
            color_http.w = 1.0f;
            ImGui::TextColored(color_http, "[■] HTTP (Hypertext Transfer)");

            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("Protocolo base de la World Wide Web para la transferencia de páginas HTML, imágenes y peticiones al servidor en texto plano (no seguro).");
            ImGui::Separator();

            // --- FILA 5: HTTPS ---
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImVec4 color_https = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo("HTTPS"));
            color_https.w = 1.0f;
            ImGui::TextColored(color_https, "[■] HTTPS (Secure Web)");

            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("Versión cifrada y segura de HTTP. Utiliza TLS/SSL para proteger las credenciales, datos bancarios y cookies frente a interceptaciones.");
            ImGui::Separator();

            // --- FILA 6: OTROS ---
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "[■] Otros / Desconocidos");

            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("Protocolos auxiliares de red o de control (como ICMP para pings, ARP para resoluciones MAC, o IGMP) que no se listaron explícitamente.");

            ImGui::EndTable();
          }

          ImGui::EndTabItem();
        }

        // PESTAÑA 3: ANALOGÍA DE LAS CAPAS DE RED (Para tus reportes académicos)
        if (ImGui::BeginTabItem("Modelo de Capas (Explicación)"))
        {
          ImGui::TextWrapped("Para entender cómo se empaquetan los datos, imagina el envío de una carta tradicional:");
          ImGui::Spacing();

          if (ImGui::CollapsingHeader("Capa 2: Enlace de Datos (El Sobre Físico)"))
          {
            ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Concepto Técnico: Cabecera Ethernet");
            ImGui::BulletText("Contiene las direcciones MAC de origen y destino.");
            ImGui::BulletText("Las MAC identifican las tarjetas de circuito físico de fábrica en tu router y tu PC.");
            ImGui::TextWrapped("Analogía: Es el sobre de papel físico que metes al buzón. No le importa lo que lleva dentro, solo las direcciones de las casas.");
          }

          if (ImGui::CollapsingHeader("Capa 3: Red (La Dirección Postal)"))
          {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Concepto Técnico: Cabecera IP");
            ImGui::BulletText("Contiene las direcciones lógicas IP de origen y destino.");
            ImGui::BulletText("Permite el ruteo del paquete a través de múltiples redes y países a través de internet.");
            ImGui::TextWrapped("Analogía: Son los datos de 'País, Ciudad, Código Postal y Calle' escritos en el frente del sobre.");
          }

          if (ImGui::CollapsingHeader("Capa 4: Transporte (El Remitente Dedicado)"))
          {
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.6f, 1.0f), "Concepto Técnico: Puertos (TCP / UDP)");
            ImGui::BulletText("Identifica qué aplicación específica de la computadora debe recibir el paquete.");
            ImGui::BulletText("Ejemplo: Puerto 80/443 es para el navegador web, puerto 53 para DNS.");
            ImGui::TextWrapped("Analogía: Es el nombre de la persona específica dentro de un edificio de departamentos a la que va dirigida la carta.");
          }

          ImGui::EndTabItem();
        }
      }
      ImGui::EndTabBar();

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

      // VENTANA DE CONTROL
      ImGui::SetNextWindowPos(ImVec2(0, menu_offset), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x, altoControl), ImGuiCond_Always);
      ImGui::Begin("Control de Sniffer", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);

      if (!captura_activa)
      {
        ImGui::Text("Estado: Detenido");
      }
      else
      {
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
      float w_excel = 110.0f;

      // Empujamos los botones a la derecha en la misma línea del texto de Estado
      ImGui::SetCursorPosX(controlWindowWidth - w_volver - w_ayuda - w_stats - w_export - w_excel - (espaciadoBotones * 4) - margenDerecho);

      bool esta_deshabilitado = captura_activa;
      if (esta_deshabilitado)
      {
        ImGui::BeginDisabled();
      }

      if (ImGui::Button("Volver", ImVec2(w_volver, 0)))
      {
        estado_actual = PANTALLA_INICIO;
      }

      if (esta_deshabilitado)
      {
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        {
          ImGui::SetTooltip("Por favor, deten la captura de trafico antes de volver al menu principal.");
        }
      }

      ImGui::SameLine();
      if (ImGui::Button("Ayuda", ImVec2(w_ayuda, 0)))
      {
        estado_anterior = SNIFFER;
        estado_actual = VENTANA_AYUDA;
      }

      ImGui::SameLine();
      static bool abrir_modal_stats = false;
      if (ImGui::Button("Estadisticas", ImVec2(w_stats, 0)))
      {
        abrir_modal_stats = true;
      }

      ImGui::SameLine();
      static bool abrir_modal_exportar = false;
      if (ImGui::Button("Exportar CSV", ImVec2(w_export, 0)))
      {
        abrir_modal_exportar = true;
      }

      ImGui::SameLine();
      static bool abrir_modal_excel = false;
      if (ImGui::Button("Exportar Excel", ImVec2(w_excel, 0)))
      {
        abrir_modal_excel = true;
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
      if (abrir_modal_exportar)
      {
        ImGui::OpenPopup("Exportar a CSV");
        abrir_modal_exportar = false;
      }

      // --- DECLARACIÓN DE VARIABLES ESTÁTICAS PARA EL MODAL (Colócalas antes de los Checkbox) ---
      static bool col_id = true, col_tiempo = true, col_longitud = true;
      static bool col_ip_o = true, col_ip_d = true, col_proto = true;
      static bool col_puerto_o = true, col_puerto_d = true;

      // Búfer para almacenar el nombre que escriba el usuario
      static char nombre_archivo[128] = "captura_trafico";

      // --- Disparador del Modal de Excel ---
      if (abrir_modal_excel)
      {
        ImGui::OpenPopup("Exportar a Excel");
        abrir_modal_excel = false;
      }

      // Variables estáticas para la configuración de columnas de Excel
      static bool ex_id = true, ex_tiempo = true, ex_longitud = true;
      static bool ex_ip_o = true, ex_ip_d = true, ex_proto = true;
      static bool ex_puerto_o = true, ex_puerto_d = true;
      static char nombre_archivo_excel[128] = "reporte_trafico";

      // --- Estructura del Modal de Excel ---
      if (ImGui::BeginPopupModal("Exportar a Excel", NULL, ImGuiWindowFlags_AlwaysAutoResize))
      {
        ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "Exportación a Formato Excel (.xlsx):");
        ImGui::Spacing();

        ImGui::InputText("Nombre del archivo", nombre_archivo_excel, IM_ARRAYSIZE(nombre_archivo_excel));
        ImGui::TextDisabled("Nota: Se forzará la compatibilidad nativa con hojas de cálculo.");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Columnas a incluir en la hoja:");
        ImGui::Spacing();
        ImGui::Checkbox("ID Paquete", &ex_id);
        ImGui::Checkbox("Tiempo de vida", &ex_tiempo);
        ImGui::Checkbox("Longitud (Bytes)", &ex_longitud);
        ImGui::Checkbox("IP Origen", &ex_ip_o);
        ImGui::Checkbox("IP Destino", &ex_ip_d);
        ImGui::Checkbox("Protocolo", &ex_proto);
        ImGui::Checkbox("Puerto Origen", &ex_puerto_o);
        ImGui::Checkbox("Puerto Destino", &ex_puerto_d);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Generar Excel", ImVec2(130, 0)))
        {
          string nombre_final_excel = nombre_archivo_excel;
          if (nombre_final_excel.empty())
          {
            nombre_final_excel = "captura_excel";
          }

          // Asegurar extensión .xlsx o .xls compatible
          if (nombre_final_excel.length() < 5 || nombre_final_excel.substr(nombre_final_excel.length() - 5) != ".xlsx")
          {
            // Usamos .xls o formato de volcado de pestañas nativo que Excel parsea directo sin romper caracteres
            if (nombre_final_excel.substr(nombre_final_excel.length() - 4) != ".xls")
            {
              nombre_final_excel += ".xls";
            }
          }

          // Para que Excel lea los datos perfectamente en columnas nativas desde C++ sin librerías pesadas,
          // el estándar de la industria es usar un flujo estructurado por tabulaciones ('\t') con cabecera de volcado.
          ofstream archivo(nombre_final_excel);
          if (archivo.is_open())
          {
            // Escribimos las cabeceras separadas por Tabuladores (delimitador oficial de Excel)
            if (ex_id)
              archivo << "Número\t";
            if (ex_tiempo)
              archivo << "Tiempo de Vida\t";
            if (ex_longitud)
              archivo << "Longitud (Bytes)\t";
            if (ex_ip_o)
              archivo << "IP Origen\t";
            if (ex_ip_d)
              archivo << "IP Destino\t";
            if (ex_proto)
              archivo << "Protocolo\t";
            if (ex_puerto_o)
              archivo << "Puerto Origen\t";
            if (ex_puerto_d)
              archivo << "Puerto Destino\t";
            archivo << "\n";

            // Bloqueo de hilos del Sniffer para lectura segura de la memoria
            paquetes_mutex.lock();
            for (const auto &pkt : lista_paquetes)
            {
              if (ex_id)
                archivo << pkt.id << "\t";
              if (ex_tiempo)
                archivo << pkt.tiempo_vida << "\t";
              if (ex_longitud)
                archivo << pkt.longitud << "\t";
              if (ex_ip_o)
                archivo << pkt.IP_origen << "\t";
              if (ex_ip_d)
                archivo << pkt.IP_destino << "\t";
              if (ex_proto)
                archivo << pkt.protocolo << "\t";
              if (ex_puerto_o)
                archivo << pkt.Puerto_origen << "\t";
              if (ex_puerto_d)
                archivo << pkt.Puerto_destino << "\t";
              archivo << "\n";
            }
            paquetes_mutex.unlock();

            archivo.close();
          }
          ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine();

        if (ImGui::Button("Cancelar", ImVec2(120, 0)))
        {
          ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
      }

      if (ImGui::BeginPopupModal("Exportar a CSV", NULL, ImGuiWindowFlags_AlwaysAutoResize))
      {
        ImGui::TextColored(ImVec4(0.0f, 0.75f, 1.0f, 1.0f), "Configuración del Archivo:");
        ImGui::Spacing();

        // Input de texto para que el usuario elija el nombre del archivo
        ImGui::InputText("Nombre del archivo", nombre_archivo, IM_ARRAYSIZE(nombre_archivo));
        ImGui::TextDisabled("Nota: Se guardará automáticamente en formato .csv");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Selecciona las columnas a exportar:");
        ImGui::Spacing();
        ImGui::Checkbox("Número de paquete", &col_id);
        ImGui::Checkbox("Tiempo de vida", &col_tiempo);
        ImGui::Checkbox("Longitud (Bytes)", &col_longitud);
        ImGui::Checkbox("IP Origen", &col_ip_o);
        ImGui::Checkbox("IP Destino", &col_ip_d);
        ImGui::Checkbox("Protocolo", &col_proto);
        ImGui::Checkbox("Puerto Origen", &col_puerto_o);
        ImGui::Checkbox("Puerto Destino", &col_puerto_d);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Exportar", ImVec2(120, 0)))
        {
          // Validación del nombre de archivo y formato final
          string nombre_final = nombre_archivo;
          if (nombre_final.empty())
          {
            nombre_final = "captura_sin_nombre";
          }
          // Si el usuario no escribió la extensión .csv, se la agregamos de forma segura
          if (nombre_final.length() < 4 || nombre_final.substr(nombre_final.length() - 4) != ".csv")
          {
            nombre_final += ".csv";
          }

          ofstream archivo(nombre_final);
          if (archivo.is_open())
          {
            string cabecera = "";
            if (col_id)
              cabecera += "Numero,";
            if (col_tiempo)
              cabecera += "Tiempo,";
            if (col_longitud)
              cabecera += "Longitud,";
            if (col_ip_o)
              cabecera += "IP Origen,";
            if (col_ip_d)
              cabecera += "IP Destino,";
            if (col_proto)
              cabecera += "Protocolo,";
            if (col_puerto_o)
              cabecera += "Puerto Origen,";
            if (col_puerto_d)
              cabecera += "Puerto Destino,";

            if (!cabecera.empty())
              cabecera.pop_back();
            archivo << cabecera << "\n";

            // Extraemos los datos paquete por paquete de forma segura
            paquetes_mutex.lock();
            for (const auto &pkt : lista_paquetes)
            {
              string linea = "";
              if (col_id)
                linea += to_string(pkt.id) + ",";
              if (col_tiempo)
                linea += pkt.tiempo_vida + ",";
              if (col_longitud)
                linea += to_string(pkt.longitud) + ",";
              if (col_ip_o)
                linea += pkt.IP_origen + ",";
              if (col_ip_d)
                linea += pkt.IP_destino + ",";
              if (col_proto)
                linea += pkt.protocolo + ",";
              if (col_puerto_o)
                linea += pkt.Puerto_origen + ",";
              if (col_puerto_d)
                linea += pkt.Puerto_destino + ",";

              if (!linea.empty())
                linea.pop_back(); // Quitamos la última coma residual
              archivo << linea << "\n";
            }
            paquetes_mutex.unlock();

            archivo.close();
          }
          ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine(); // Botón cancelar a un lado

        if (ImGui::Button("Cancelar", ImVec2(120, 0)))
        {
          ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
      }
      ImGui::End();

      // Panel de estadísticas
      // --- Disparador del Modal de Estadísticas ---
      if (abrir_modal_stats)
      {
        ImGui::OpenPopup("Gráfico de Tráfico");
        abrir_modal_stats = false;
      }

      // --- Estructura del Modal de Estadísticas ---
      if (ImGui::BeginPopupModal("Gráfico de Tráfico", NULL, ImGuiWindowFlags_AlwaysAutoResize))
      {
        map<string, int> conteo_protocolos;
        int total_paquetes = 0;

        paquetes_mutex.lock();
        total_paquetes = lista_paquetes.size();
        for (const auto &pkt : lista_paquetes)
        {
          conteo_protocolos[pkt.protocolo]++;
        }
        paquetes_mutex.unlock();

        // Dibujamos la interfaz interna
        if (total_paquetes > 0)
        {
          ImGui::TextColored(ImVec4(0.0f, 0.75f, 1.0f, 1.0f), "Métricas de Captura Actual:");
          ImGui::Spacing();
          ImGui::Text("Total de paquetes en la red: %d", total_paquetes);
          ImGui::Separator();
          ImGui::Spacing();

          // Recorremos el mapa de resultados
          for (auto const &[proto, count] : conteo_protocolos)
          {
            float porcentaje = (float)count / total_paquetes;

            // Texto alineado a la izquierda
            ImGui::Text("%s:", proto.c_str());

            // Texto numérico centrado
            ImGui::SameLine(120.0f);
            ImGui::Text("%d (%.1f%%)", count, porcentaje * 100.0f);

            // Barra a la derecha
            ImGui::SameLine(240.0f);

            // Obtener color con opacidad completa para la barra de progreso
            ImVec4 color_barra = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo(proto));
            color_barra.w = 1.0f;

            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color_barra);
            ImGui::ProgressBar(porcentaje, ImVec2(250.0f, 15.0f), "");
            ImGui::PopStyleColor();
          }
        }
        else
        {
          ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "Aún no hay tráfico capturado para graficar.");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Botón inferior para cerrar el modal de forma limpia
        if (ImGui::Button("Cerrar", ImVec2(120, 0)))
        {
          ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
      }

      // iniciamos la segunda seccion grafica donde se muestra todo el trafico capturado
      ImGui::SetNextWindowPos(ImVec2(0, menu_offset + altoControl), ImGuiCond_Always);
      ImGui::SetNextWindowSize(ImVec2(viewportSize.x, altoTabla), ImGuiCond_Always);
      ImGui::Begin("Monitoreo de Tráfico", NULL, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);

      if (ImGui::BeginTabBar("TabsControlTrafico"))
      {
        // -------------------------------------------------------------------------------
        // PESTAÑA A: TABLA DE PAQUETES (Tu código original intacto)
        // -------------------------------------------------------------------------------
        if (ImGui::BeginTabItem("Vista de Tabla"))
        {
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

            if (ip_o[0] == '\0' && ip_d[0] == '\0' && proto[0] == '\0' && puerto_d[0] == '\0' && puerto_o[0] == '\0')
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
                if (ImGui::IsItemHovered())
                {
                  ImGui::BeginTooltip();
                  ImGui::Text("%s", obtenerTipoIP(pkt.IP_origen).c_str());
                  ImGui::EndTooltip();
                }
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", pkt.IP_destino.c_str());
                if (ImGui::IsItemHovered())
                {
                  ImGui::BeginTooltip();
                  ImGui::Text("%s", obtenerTipoIP(pkt.IP_destino).c_str());
                  ImGui::EndTooltip();
                }
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
                if (filtro_condicion_y)
                {
                  mostrar = ((ip_o[0] == '\0' || strcmp(ip_o, pkt.IP_origen.c_str()) == 0) && (ip_d[0] == '\0' || strcmp(ip_d, pkt.IP_destino.c_str()) == 0) && (proto[0] == '\0' || strcmp(proto, pkt.protocolo.c_str()) == 0) && (puerto_d[0] == '\0' || strcmp(puerto_d, pkt.Puerto_destino.c_str()) == 0) && (puerto_o[0] == '\0' || strcmp(puerto_o, pkt.Puerto_origen.c_str()) == 0));
                }
                else
                {
                  bool coincide_ip_o = (ip_o[0] != '\0' && strcmp(ip_o, pkt.IP_origen.c_str()) == 0);
                  bool coincide_ip_d = (ip_d[0] != '\0' && strcmp(ip_d, pkt.IP_destino.c_str()) == 0);
                  bool coincide_proto = (proto[0] != '\0' && strcmp(proto, pkt.protocolo.c_str()) == 0);
                  bool coincide_puerto_o = (puerto_o[0] != '\0' && strcmp(puerto_o, pkt.Puerto_origen.c_str()) == 0);
                  bool coincide_puerto_d = (puerto_d[0] != '\0' && strcmp(puerto_d, pkt.Puerto_destino.c_str()) == 0);
                  mostrar = (coincide_ip_o || coincide_ip_d || coincide_proto || coincide_puerto_o || coincide_puerto_d);
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
          ImGui::EndTabItem();
        }

        // -------------------------------------------------------------------------------
        // PESTAÑA B: EL MAPA EN TIEMPO REAL (Traffic Animation Canvas)
        // -------------------------------------------------------------------------------
        if (ImGui::BeginTabItem("Mapa de Paquetes Viajeros"))
        {
          // 1. Sincronizar hilos de manera segura: Leer nuevos paquetes y crear esferas viajeras
          paquetes_mutex.lock();
          for (const auto &pkt : lista_paquetes)
          {
            if (pkt.id > ultimo_id_procesado_esfera)
            {
              EsferaViajera nueva_esfera;
              nueva_esfera.progreso = 0.0f;
              nueva_esfera.velocidad = 1.4f; // Velocidad de la animación

              // Extraer el color real del protocolo mapeado en tu función
              nueva_esfera.color = ImGui::ColorConvertU32ToFloat4(ObtenerColorProtocolo(pkt.protocolo));
              nueva_esfera.color.w = 1.0f; // Asegurar opacidad total

              // Detectar dirección analizando IPs conocidas de redes internas privadas
              if (pkt.IP_origen.rfind("192.168.", 0) == 0 || pkt.IP_origen.rfind("10.", 0) == 0 || pkt.IP_origen.rfind("172.", 0) == 0)
              {
                nueva_esfera.deUsuarioANube = true; // PC -> Internet
              }
              else
              {
                nueva_esfera.deUsuarioANube = false; // Internet -> PC
              }

              // Evitar sobrecargar la memoria (máximo 70 esferas simultáneas si el tráfico vuela)
              if (esferas_activas.size() < 70)
              {
                esferas_activas.push_back(nueva_esfera);
              }
              ultimo_id_procesado_esfera = pkt.id;
            }
          }
          paquetes_mutex.unlock();

          // 2. Preparar lienzo de dibujo técnico de ImGui
          ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
          ImVec2 canvas_size = ImGui::GetContentRegionAvail();
          if (canvas_size.y < 100.0f)
            canvas_size.y = 100.0f;

          ImDrawList *draw_list = ImGui::GetWindowDrawList();

          // Fondo del Canvas
          // Obtiene el color de fondo de cuadro (FrameBg) del estilo actual de tu interfaz
          ImU32 color_fondo_estilo = ImGui::GetColorU32(ImGuiCol_FrameBg);

          // Dibuja el fondo usando el color oficial de tu tema de ImGui
          draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), color_fondo_estilo, 6.0f);
          draw_list->AddRect(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), ImGui::GetColorU32(ImGuiCol_Border), 6.0f);

          // 3. Posiciones de nodos (Computadora e Internet)
          ImVec2 pc_pos = ImVec2(canvas_pos.x + 120.0f, canvas_pos.y + (canvas_size.y * 0.5f));
          ImVec2 nube_pos = ImVec2(canvas_pos.x + canvas_size.x - 120.0f, canvas_pos.y + (canvas_size.y * 0.5f));

          // Enlace de datos de fondo
          draw_list->AddLine(pc_pos, nube_pos, IM_COL32(60, 65, 75, 255), 2.0f);

          // 4. Dibujar Elemento Visual de la Computadora (Tu PC)
          draw_list->AddRectFilled(ImVec2(pc_pos.x - 22, pc_pos.y - 14), ImVec2(pc_pos.x + 22, pc_pos.y + 10), IM_COL32(0, 180, 216, 255), 4.0f); // Monitor
          draw_list->AddRect(ImVec2(pc_pos.x - 22, pc_pos.y - 14), ImVec2(pc_pos.x + 22, pc_pos.y + 10), IM_COL32(255, 255, 255, 200), 4.0f, 0, 1.5f);
          draw_list->AddTriangleFilled(ImVec2(pc_pos.x - 10, pc_pos.y + 20), ImVec2(pc_pos.x + 10, pc_pos.y + 20), ImVec2(pc_pos.x, pc_pos.y + 10), IM_COL32(100, 110, 120, 255)); // Base
          draw_list->AddRectFilled(ImVec2(pc_pos.x - 25, pc_pos.y + 20), ImVec2(pc_pos.x + 25, pc_pos.y + 24), IM_COL32(80, 90, 100, 255), 2.0f);                                  // Teclado
          draw_list->AddText(ImVec2(pc_pos.x - 24, pc_pos.y - 32), ImGui::GetColorU32(ImGuiCol_Text), "LOCAL PC");

          // 5. Dibujar Elemento Visual de la Nube (Internet / Remoto)
          draw_list->AddCircleFilled(ImVec2(nube_pos.x, nube_pos.y), 16.0f, IM_COL32(114, 9, 183, 255));
          draw_list->AddCircleFilled(ImVec2(nube_pos.x - 14, nube_pos.y + 6), 12.0f, IM_COL32(114, 9, 183, 255));
          draw_list->AddCircleFilled(ImVec2(nube_pos.x + 14, nube_pos.y + 6), 12.0f, IM_COL32(114, 9, 183, 255));
          draw_list->AddCircleFilled(ImVec2(nube_pos.x - 7, nube_pos.y - 10), 13.0f, IM_COL32(114, 9, 183, 255));
          draw_list->AddCircleFilled(ImVec2(nube_pos.x + 7, nube_pos.y - 10), 13.0f, IM_COL32(114, 9, 183, 255));
          draw_list->AddText(ImVec2(nube_pos.x - 28, nube_pos.y - 32), ImGui::GetColorU32(ImGuiCol_Text), "INTERNET");

          // 6. Actualización cinemática y renderizado del paso de las esferas
          float deltaTime = ImGui::GetIO().DeltaTime;

          for (auto it = esferas_activas.begin(); it != esferas_activas.end();)
          {
            it->progreso += it->velocidad * deltaTime;

            if (it->progreso >= 1.0f)
            {
              it = esferas_activas.erase(it); // Llegó al destino, eliminar de cola
              continue;
            }

            // Interpolación Lineal (Lerp) para calcular el movimiento por píxeles en pantalla
            ImVec2 punto_actual;
            if (it->deUsuarioANube)
            {
              punto_actual.x = pc_pos.x + (nube_pos.x - pc_pos.x) * it->progreso;
            }
            else
            {
              punto_actual.x = nube_pos.x - (nube_pos.x - pc_pos.x) * it->progreso;
            }
            punto_actual.y = pc_pos.y; // Se mueven de forma recta por el cable coaxial imaginario

            ImU32 color_esfera = ImGui::ColorConvertFloat4ToU32(it->color);

            // Dibujar Esfera
            draw_list->AddCircleFilled(punto_actual, 7.0f, color_esfera);
            // Efecto halo exterior (brillo neón)
            draw_list->AddCircle(punto_actual, 9.5f, (color_esfera & 0x00FFFFFF) | 0x66000000, 0, 1.5f);

            it++;
          }
          ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
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
          PaqueteInfo *pkt_actual = nullptr;

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

  // De ANSI a WideChar (UTF-16)

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
  for (char &c : desc_lower)
  {
    c = tolower(c);
  }

  if (desc_lower.find("virtualbox") != string::npos)
    return "[VirtualBox]";
  if (desc_lower.find("vmware") != string::npos)
    return "[VMware]";
  if (desc_lower.find("loopback") != string::npos)
    return "[Loopback]";
  if (desc_lower.find("virtual") != string::npos)
    return "[Virtual]";

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
string obtenerTipoIP(const string &ip)
{
  if (ip == "N/A" || ip.empty())
    return "IP no disponible.";
  if (ip == "255.255.255.255")
    return "Direccion de Broadcast (Envia datos a toda la red local).";

  int o1, o2, o3, o4;
  // Extraemos los 4 octetos matematicamente para analizarlos
  if (sscanf_s(ip.c_str(), "%d.%d.%d.%d", &o1, &o2, &o3, &o4) == 4)
  {
    // Rangos de IP Privada
    if (o1 == 10)
      return "IP Privada (Clase A - Comun en redes empresariales o virtuales).";
    if (o1 == 172 && (o2 >= 16 && o2 <= 31))
      return "IP Privada (Clase B - Red local).";
    if (o1 == 192 && o2 == 168)
      return "IP Privada (Clase C - Red local casera tipica).";

    // Direcciones especiales
    if (o1 == 127)
      return "Direccion Loopback (Trafico interno de tu propia maquina).";
    if (o1 == 169 && o2 == 254)
      return "Direccion Link-Local (APIPA - Asignada cuando no hay internet/DHCP).";
    if (o1 >= 224 && o1 <= 239)
      return "Direccion Multicast (Transmision a un grupo especifico de equipos).";

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

  if (filtro_condicion_y)
  {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.6f, 0.2f, 1.0f));
    if (ImGui::Button("Todos los filtros"))
      filtro_condicion_y = false;
  }
  else
  {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.4f, 0.0f, 1.0f));
    if (ImGui::Button("Cualquiera de los filtros"))
      filtro_condicion_y = true;
  }
  ImGui::PopStyleColor();
  if (ImGui::IsItemHovered())
  {
    ImGui::BeginTooltip();
    if (filtro_condicion_y)
    {
      ImGui::TextUnformatted("Filtro estricto:\nSolo se muestran los paquetes que tengan\nel protocolo, las IPs y los puertos que escribiste.");
    }
    else
    {
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
  ImGui::Text("Puerto origen:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(80);

  const char *puerto_ori;
  if (puerto_o[0] == '\0')
  {
    puerto_ori = "Todos";
  }
  else
  {
    puerto_ori = puerto_o;
  }

  if (ImGui::BeginCombo("##combo_puertos_ori", puerto_ori))
  {
    // Opción por defecto para limpiar el filtro
    bool p_todos_sel = (puerto_o[0] == '\0');
    if (ImGui::Selectable("Todos", p_todos_sel))
    {
      puerto_o[0] = '\0';
    }

    for (const auto &puerto : puertos_origen)
    {
      bool esta_sel = (strcmp(puerto_o, puerto.c_str()) == 0);
      if (ImGui::Selectable(puerto.c_str(), esta_sel))
      {
        snprintf(puerto_o, sizeof(puerto_o), "%s", puerto.c_str());
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

void StyleColorsUmisumi()
{
  ImGuiStyle &style = ImGui::GetStyle();
  ImVec4 *colors = style.Colors;

  // --- COLOR DE LETRA EN NEGRO POR DEFECTO ---
  colors[ImGuiCol_Text] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
  colors[ImGuiCol_TextDisabled] = ImVec4(0.40f, 0.40f, 0.40f, 1.00f);

  // Configuración del fondo y paneles
  colors[ImGuiCol_WindowBg] = ImVec4(0.92f, 1.00f, 0.94f, 1.00f);
  colors[ImGuiCol_ChildBg] = ImVec4(0.85f, 0.95f, 0.88f, 0.00f); // Transparente o sutil
  colors[ImGuiCol_PopupBg] = ImVec4(0.92f, 1.00f, 0.94f, 0.98f);
  colors[ImGuiCol_Border] = ImVec4(0.00f, 0.54f, 0.21f, 0.35f);

  // Elementos de interacción (Inputs, Combos, Checkbox)
  colors[ImGuiCol_FrameBg] = ImVec4(0.71f, 0.97f, 0.84f, 1.00f);
  colors[ImGuiCol_FrameBgHovered] = ImVec4(0.26f, 0.98f, 0.60f, 0.40f);
  colors[ImGuiCol_FrameBgActive] = ImVec4(0.26f, 0.98f, 0.65f, 0.67f);

  // Títulos de ventanas
  colors[ImGuiCol_TitleBg] = ImVec4(0.42f, 0.95f, 0.59f, 1.00f);
  colors[ImGuiCol_TitleBgActive] = ImVec4(0.15f, 0.84f, 0.37f, 1.00f);
  colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.42f, 0.95f, 0.59f, 0.75f);
  colors[ImGuiCol_MenuBarBg] = ImVec4(0.00f, 0.54f, 0.21f, 1.00f);

  // Barras de desplazamiento
  colors[ImGuiCol_ScrollbarBg] = ImVec4(0.85f, 0.95f, 0.88f, 1.00f);
  colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.00f, 0.58f, 0.19f, 0.80f);
  colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.25f, 0.81f, 0.50f, 0.80f);
  colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.32f, 0.87f, 0.51f, 1.00f);

  // Checkmarks y Sliders
  colors[ImGuiCol_CheckMark] = ImVec4(0.08f, 0.67f, 0.40f, 1.00f);
  colors[ImGuiCol_SliderGrab] = ImVec4(0.26f, 0.98f, 0.56f, 0.78f);
  colors[ImGuiCol_SliderGrabActive] = ImVec4(0.46f, 0.80f, 0.59f, 0.60f);

  // Botones (Estilo verde Umisumi, sin el azul que molestaba)
  colors[ImGuiCol_Button] = ImVec4(0.26f, 0.98f, 0.67f, 0.57f);
  colors[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.98f, 0.54f, 1.00f);
  colors[ImGuiCol_ButtonActive] = ImVec4(0.06f, 0.98f, 0.42f, 1.00f);

  // Cabeceras de tablas y menús desplegables
  colors[ImGuiCol_Header] = ImVec4(0.26f, 0.98f, 0.56f, 0.31f);
  colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.98f, 0.54f, 0.80f);
  colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.98f, 0.54f, 1.00f);

  colors[ImGuiCol_Separator] = ImVec4(0.00f, 0.54f, 0.21f, 0.35f);
  colors[ImGuiCol_SeparatorHovered] = ImVec4(0.14f, 0.80f, 0.36f, 0.78f);
  colors[ImGuiCol_SeparatorActive] = ImVec4(0.14f, 0.80f, 0.38f, 1.00f);
  colors[ImGuiCol_ResizeGrip] = ImVec4(0.26f, 0.98f, 0.56f, 0.20f);
  colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.26f, 0.98f, 0.52f, 0.67f);
  colors[ImGuiCol_ResizeGripActive] = ImVec4(0.26f, 0.98f, 0.52f, 0.95f);

  // Pestañas (Tabs)
  colors[ImGuiCol_Tab] = ImVec4(0.76f, 0.84f, 0.79f, 0.93f);
  colors[ImGuiCol_TabHovered] = ImVec4(0.26f, 0.98f, 0.54f, 0.80f);
  colors[ImGuiCol_TabSelected] = ImVec4(0.60f, 0.88f, 0.70f, 1.00f);
  colors[ImGuiCol_TabSelectedOverline] = ImVec4(0.26f, 0.98f, 0.56f, 1.00f);
  colors[ImGuiCol_TabDimmed] = ImVec4(0.92f, 0.94f, 0.93f, 0.99f);
  colors[ImGuiCol_TabDimmedSelected] = ImVec4(0.74f, 0.91f, 0.82f, 1.00f);

  colors[ImGuiCol_TableHeaderBg] = ImVec4(0.78f, 0.98f, 0.85f, 1.00f);
  colors[ImGuiCol_TableBorderStrong] = ImVec4(0.00f, 0.54f, 0.21f, 0.35f);
  colors[ImGuiCol_TableBorderLight] = ImVec4(0.00f, 0.54f, 0.21f, 0.15f);

  colors[ImGuiCol_TextLink] = ImVec4(0.00f, 0.54f, 0.21f, 1.00f);
  colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.98f, 0.54f, 0.35f);
  colors[ImGuiCol_DragDropTarget] = ImVec4(0.26f, 0.98f, 0.54f, 0.95f);
  colors[ImGuiCol_NavCursor] = ImVec4(0.26f, 0.98f, 0.50f, 0.80f);
}

// --- LOGICA DE TRADUCCIÓN METAFÓRICA (MODO RAYOS X) ---
DetallePaqueteCapas TraducirPaqueteACapas(const PaqueteInfo &pkt)
{
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

  if (pkt.protocolo == "TCP" || pkt.protocolo == "HTTP" || pkt.protocolo == "HTTPS" || pkt.protocolo == "SSH / SFTP" || pkt.protocolo == "Telnet")
  {
    xray.transporte.analogia = "Envio Certificado (TCP): Es una entrega que exige firma de recibido. Tu computadora y el servidor aseguran que ningun fragmento de la carta se pierda o llegue roto.";
    char buf_trans[256];
    snprintf(buf_trans, sizeof(buf_trans), "TCP | Puerto Origen: %s -> Puerto Destino: %s", pkt.Puerto_origen.c_str(), pkt.Puerto_destino.c_str());
    xray.transporte.detalles_tecnicos = buf_trans;
  }
  else if (pkt.protocolo == "UDP" || pkt.protocolo == "DNS" || pkt.protocolo == "NTP" || pkt.protocolo == "DHCP (Server)" || pkt.protocolo == "DHCP (Client)")
  {
    xray.transporte.analogia = "Envio Rapido (UDP): Es como lanzar volantes desde un avion. No importa si alguno se vuela o se pierde, lo crucial es que llegue de inmediato. Ideal para juegos, streaming o consultas veloces.";
    char buf_trans[256];
    snprintf(buf_trans, sizeof(buf_trans), "UDP | Puerto Origen: %s -> Puerto Destino: %s", pkt.Puerto_origen.c_str(), pkt.Puerto_destino.c_str());
    xray.transporte.detalles_tecnicos = buf_trans;
  }
  else
  {
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
void DibujarModoCapas(const DetallePaqueteCapas &paquete)
{
  ImGui::TextUnformatted("Modo Capas");
  ImGui::Separator();
  ImGui::Spacing();

  static string capa_abierta = "";
  static int ultimo_id_visto = -1;

  // Si cambiamos de paquete en la tabla, cerramos la inspección previa
  if (idPaqueteSeleccionado != ultimo_id_visto)
  {
    capa_abierta = "";
    ultimo_id_visto = idPaqueteSeleccionado;
  }

  float ancho_disponible = ImGui::GetContentRegionAvail().x;
  float alto_boton = 32.0f;

  // CAPA 1: ENLACE (Camión)
  ImGui::PushStyleColor(ImGuiCol_Button, paquete.enlace.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.enlace.color.x + 0.08f, paquete.enlace.color.y + 0.08f, paquete.enlace.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Enlace (El Camion de Mensajeria)", ImVec2(ancho_disponible, alto_boton)))
  {
    capa_abierta = "Enlace";
  }
  ImGui::PopStyleColor(2);

  // CAPA 2: RED (El Sobre)
  ImGui::Indent(20.0f);
  ancho_disponible -= 40.0f;

  ImGui::PushStyleColor(ImGuiCol_Button, paquete.red.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.red.color.x + 0.08f, paquete.red.color.y + 0.08f, paquete.red.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Red (El Sobre Postal)", ImVec2(ancho_disponible, alto_boton)))
  {
    capa_abierta = "Red";
  }
  ImGui::PopStyleColor(2);

  // CAPA 3: TRANSPORTE (Tipo de Envío)
  ImGui::Indent(20.0f);
  ancho_disponible -= 40.0f;

  ImGui::PushStyleColor(ImGuiCol_Button, paquete.transporte.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.transporte.color.x + 0.08f, paquete.transporte.color.y + 0.08f, paquete.transporte.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Transporte (Forma de Envio)", ImVec2(ancho_disponible, alto_boton)))
  {
    capa_abierta = "Transporte";
  }
  ImGui::PopStyleColor(2);

  // CAPA 4: DATOS (La Carta)
  ImGui::Indent(20.0f);
  ancho_disponible -= 40.0f;

  ImGui::PushStyleColor(ImGuiCol_Button, paquete.datos.color);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(paquete.datos.color.x + 0.08f, paquete.datos.color.y + 0.08f, paquete.datos.color.z + 0.08f, 1.0f));
  if (ImGui::Button("Capa de Datos (La Carta Secreta)", ImVec2(ancho_disponible, alto_boton)))
  {
    capa_abierta = "Datos";
  }
  ImGui::PopStyleColor(2);

  // Restauramos las sangrías de la pila gráfica de ImGui
  ImGui::Unindent(60.0f);

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  // PANEL DINÁMICO DE DETALLES
  if (!capa_abierta.empty())
  {
    ImGui::BeginChild("PanelCapasExplicacion", ImVec2(0, 120), true, ImGuiWindowFlags_None);

    const CapaTraducida *capa_actual = nullptr;
    if (capa_abierta == "Enlace")
      capa_actual = &paquete.enlace;
    else if (capa_abierta == "Red")
      capa_actual = &paquete.red;
    else if (capa_abierta == "Transporte")
      capa_actual = &paquete.transporte;
    else if (capa_abierta == "Datos")
      capa_actual = &paquete.datos;

    if (capa_actual)
    {
      ImGui::TextColored(ImVec4(0.00f, 0.54f, 0.21f, 1.00f), "Explicacion Sencilla:");
      ImGui::SameLine();
      ImGui::TextWrapped("%s", capa_actual->analogia);

      ImGui::Spacing();

      ImGui::TextColored(ImVec4(0.15f, 0.45f, 0.85f, 1.00f), "Datos Tecnicos Reales:");
      ImGui::SameLine();
      ImGui::TextWrapped("%s", capa_actual->detalles_tecnicos.c_str());
    }
    ImGui::EndChild();
  }
  else
  {
    ImGui::TextDisabled("Haz clic en cualquiera de los bloques de color apilados arriba para examinar su contenido.");
  }
}