===========================================================================
GUÍA PASO A PASO: CONFIGURACIÓN DE NPCAP, GLFW E IMGUI EN VS CODE (WINDOWS)
===========================================================================

---------------------------------------------------------------------------
PARTE 1: DESCARGA E INSTALACIÓN DE NPCAP
---------------------------------------------------------------------------
Para que tu sniffer pueda capturar paquetes en Windows, necesitas el Driver 
de Npcap (para ejecutar) y el SDK (para programar).

1. INSTALADOR DE NPCAP:
   - Ve al sitio oficial: https://npcap.com/#download
   - Descarga el instalador ejecutable (ej. "Npcap 1.88 installer").
   - Ejecútalo como Administrador.
   - ¡CRUCIAL!: Durante la instalación, asegúrate de MARCAR la casilla:
     "WinPcap API-compatible mode". Si no la marcas, el compilador fallará.

2. NPCAP SDK:
   - En la misma página, busca la sección del SDK y descarga el ZIP 
     (ej. "Npcap SDK 1.16").
   - Descomprime el archivo ZIP.
   - Cambia el nombre de la carpeta descomprimida a "npcap-sdk" y muévela 
     directamente al disco C:. La ruta debe quedar exactamente así:
     C:\npcap-sdk\

---------------------------------------------------------------------------
PARTE 2: INSTALACIÓN DE GLFW (DENTRO DE MSYS2)
---------------------------------------------------------------------------
GLFW se encargará de crear la ventana gráfica y gestionar el teclado/mouse. 
Como usas g++ de MSYS2, lo instalaremos directamente mediante su gestor de paquetes.

1. Abre la terminal de "MSYS2 UCRT64" en tu computadora (o usa la terminal 
   integrada de VS Code si apunta a MSYS2).
2. Escribe el siguiente comando exacto y presiona Enter:
   
   pacman -S mingw-w64-ucrt-x86_64-glfw

3. Cuando la terminal te pregunte si deseas proceder con la instalación, 
   presiona la tecla 'Y' (o 'S' si está en español) y dale Enter.
4. Reinicia VS Code después de que termine para asegurar que detecte la librería.

---------------------------------------------------------------------------
PARTE 4: ARCHIVOS DE CONFIGURACIÓN DE VS CODE
---------------------------------------------------------------------------
Ve a la carpeta ".vscode" dentro de tu proyecto y asegúrate de que los 
siguientes dos archivos contengan este código exacto:

-----------------------------------------
1. ARCHIVO: c_cpp_properties.json
-----------------------------------------
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                "${workspaceFolder}/**",
                "C:/npcap-sdk/Include",
                "${workspaceFolder}/imgui",
                "${workspaceFolder}/imgui/backends"
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE",
                "WPCAP"
            ],
            "compilerPath": "C:/msys64/ucrt64/bin/g++.exe",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-gcc-x64"
        }
    ],
    "version": 4
}

-----------------------------------------
2. ARCHIVO: tasks.json
-----------------------------------------
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "cppbuild",
            "label": "Compilar Sniffer con Npcap e ImGui",
            "command": "C:/msys64/ucrt64/bin/g++.exe",
            "args": [
                "-fdiagnostics-color=always",
                "-g",
                "${workspaceFolder}/src/*.cpp",
                "${workspaceFolder}/imgui/*.cpp",
                "${workspaceFolder}/imgui/backends/imgui_impl_glfw.cpp",
                "${workspaceFolder}/imgui/backends/imgui_impl_opengl3.cpp",
                "-o", "${workspaceFolder}\\sniffer.exe",
                "-I", "C:/npcap-sdk/Include",
                "-I", "${workspaceFolder}/imgui",
                "-I", "${workspaceFolder}/imgui/backends",
                "-L", "C:/npcap-sdk/Lib/x64",
                "-lwpcap", 
                "-lPacket",
                "-lglfw3",
                "-lgdi32",
                "-lopengl32"
            ],
            "options": {
                "cwd": "C:/msys64/ucrt64/bin"
            },
            "problemMatcher": [
                "$gcc"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            }
        }
    ]
}

---------------------------------------------------------------------------
PARTE 4: CÓMO COMPILAR Y EJECUTAR
---------------------------------------------------------------------------
1. Abre tu archivo de código (`src/sniffer.cpp`).
2. Presiona las teclas: Ctrl + Shift + B.
   2.1 En caso de aparecer varias opciones seleccionar la que dice: 
      "Compilar Sniffer con Npcap e ImGui".
3. El compilador procesará todos los archivos. Al finalizar con éxito, se 
   creará un archivo ejecutable llamado `sniffer.exe` en la raíz de tu proyecto.
4. Para ejecutarlo desde la terminal de VS Code, escribe:
   ./sniffer.exe

---------------------------------------------------------------------------
PARTE 5: TODO FUNCIONANDO
---------------------------------------------------------------------------
Para comprobar que todo fue instalado correctamante es necesario compilar 
por primera vez el proyecto, de esta forma se comprobará que el entorno 
gráfico funciona correctamente.

En caso de la libreria NPCAP es necesario cambiar el código base por el 
siguiente y volver a compilar:

---------------------------------------------------------------------------
#define WPCAP
#include <pcap.h>
#include <iostream>

using namespace std;

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        cout << "Error al buscar interfaces: " << errbuf << endl;
        return 1;
    }

    cout << "¡Npcap configurado con exito!" << endl;
    cout << "Interfaces encontradas:" << endl;

    for (pcap_if_t *d = interfaces; d != NULL; d = d->next) {
        cout << "- " << (d->description ? d->description : d->name) << endl;
    }

    pcap_freealldevs(interfaces);
    return 0;
}
---------------------------------------------------------------------------

---------------------------------------------------------------------------
* NOTA DE REDES: Para capturar paquetes reales a través del driver de Npcap, 
  deberás abrir VS Code como Administrador (clic derecho sobre el icono de 
  VS Code -> Ejecutar como administrador).
===========================================================================