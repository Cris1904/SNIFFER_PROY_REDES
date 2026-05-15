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
PARTE 3: CÓMO COMPILAR Y EJECUTAR
---------------------------------------------------------------------------
1. Abre tu archivo de código (`src/sniffer.cpp`).
2. Presiona las teclas: Ctrl + Shift + B.
3. El compilador procesará todos los archivos. Al finalizar con éxito, se 
   creará un archivo ejecutable llamado `sniffer.exe` en la raíz de tu proyecto.
4. Para ejecutarlo desde la terminal de VS Code, escribe:
   ./sniffer.exe

---------------------------------------------------------------------------
* NOTA DE REDES: Para capturar paquetes reales a través del driver de Npcap, 
  deberás abrir VS Code como Administrador (clic derecho sobre el icono de 
  VS Code -> Ejecutar como administrador).
===========================================================================