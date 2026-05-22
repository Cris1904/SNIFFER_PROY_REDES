#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <ctime>
#include <vector>
#include <string>
#include <mutex>

using namespace std;

/*----- FUNCIONES CAPTURA DE PAQUETES -----*/
BOOL LoadNpcapDlls()
{
  _TCHAR npcap_dir[512];
  UINT len;
  len = GetSystemDirectory(npcap_dir, 480);
  if (!len) {
    fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
    return FALSE;
  }
  _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
  if (SetDllDirectory(npcap_dir) == 0) {
    fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
    return FALSE;
  }
  return TRUE;
}

/* 4 bytes IP address */
typedef struct ip_address{
  u_char byte1;
  u_char byte2;
  u_char byte3;
  u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
  u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
  u_char  tos;     // Type of service 
  u_short tlen;    // Total length 
  u_short identification; // Identification
  u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
  u_char  ttl;      // Time to live
  u_char  proto;    // Protocol
  u_short crc;      // Header checksum
  ip_address  saddr; // Source address
  ip_address  daddr; // Destination address
  u_int  op_pad;     // Option + Padding
}ip_header;

/* IPv6 header (pendiente) */

/* TCP header */
typedef struct tcp_header {
    u_short sport;       // Source port
    u_short dport;       // Destination port
    u_int   seq;         // Sequence number
    u_int   ack;         // Acknowledgement number
    u_char  offx2;       // Data offset, rsvd
    u_char  flags;       // Control flags
    u_short win;         // Window
    u_short crc;         // Checksum
    u_short urp;         // Urgent pointer
}tcp_header;

/* UDP header*/
typedef struct udp_header{
  u_short sport; // Source port
  u_short dport; // Destination port
  u_short len;   // Datagram length
  u_short crc;   // Checksum
}udp_header;


// CAMBIAR A CLASES Estructuras para almacenar la información limpia
class PaqueteInfo{
  public:
  int id;
  string tiempo_vida;
  int longitud;
  string IP_origen;
  string IP_destino;
  string protocolo;
  string Puerto_origen;
  string Puerto_destino;
  PaqueteInfo(int id, string tiempo_vida, int longitud, string IP_origen, string IP_destino, string protocolo, string Puerto_origen, string Puerto_destino){
    this-> id=id;
    this-> tiempo_vida=tiempo_vida;
    this-> longitud=longitud;
    this-> IP_origen=IP_origen;
    this-> IP_destino=IP_destino;
    this-> protocolo=protocolo;
    this-> Puerto_origen=Puerto_origen;
    this-> Puerto_destino=Puerto_destino;
  }
};

// Para poder agregar más datos a mostrar más a delante
class PaqueteInfo_UDP : public PaqueteInfo{
  public:
  using PaqueteInfo::PaqueteInfo;
  
};

// Para poder agregar más datos a mostrar más a delante
class PaqueteInfo_TCP : public PaqueteInfo{
  public:
  using PaqueteInfo::PaqueteInfo;
};

/* ---- Variables globales compartidas entre Npcap e ImGui ----*/
// Vector que guardara todos los paquetes que van llegando de forma dinámica
vector<PaqueteInfo> lista_paquetes; // CAMBIAR A CLASES FALTAN AGREGAR LOS DEMÁS PARA LOS OTRO PROTOCOLOS
// Variable que nos ayudará a que no se afecten los paquetes por el uso de su llegada y la interfaz
mutex paquetes_mutex;              
bool captura_activa = false;        
// Variable poder detener la captura     
pcap_t* adhandle_global = NULL; 
// Hora en que inicio la captura
time_t hora_global_inicio;
// ID del paquete
int id=0;

// Función para establecer el protocolo
string asignar_protocolo(u_short sport, u_short dport, u_char ip_proto) {
  // Si es UDP
  if (ip_proto == 17) {
    if (sport == 53 || dport == 53)   return "DNS";
    if (sport == 67 || dport == 67)   return "DHCP (Server)";
    if (sport == 68 || dport == 68)   return "DHCP (Client)";
    if (sport == 69 || dport == 69)   return "TFTP";
    if (sport == 123 || dport == 123) return "NTP";
    if (sport == 161 || dport == 161) return "SNMP";
    if (sport == 443 || dport == 443) return "HTTP/3";
    if (sport == 514 || dport == 514) return "Syslog";
    return "UDP";
  }
  // Si es TCP
  else if (ip_proto == 6) {
    if (sport == 20 || dport == 20)   return "FTP (Data)";
    if (sport == 21 || dport == 21)   return "FTP (Control)";
    if (sport == 22 || dport == 22)   return "SSH / SFTP";
    if (sport == 23 || dport == 23)   return "Telnet";
    if (sport == 25 || dport == 25)   return "SMTP";
    if (sport == 80 || dport == 80)   return "HTTP";
    if (sport == 110 || dport == 110) return "POP3";
    if (sport == 143 || dport == 143) return "IMAP";
    if (sport == 179 || dport == 179) return "BGP";
    if (sport == 389 || dport == 389) return "LDAP";
    if (sport == 443 || dport == 443) return "HTTPS";
    if (sport == 445 || dport == 445) return "SMB";
    if (sport == 587 || dport == 587) return "SMTP (Seguro)";
    if (sport == 636 || dport == 636) return "LDAPS";
    if (sport == 993 || dport == 993) return "IMAPS";
    return "TCP";
  }
  return "nadota";
}

// Funci+on encargada de organizar el paquete que llegó
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  struct tm ltime;            // Estructura de tiempo desglosada (horas, minutos, segundos)
  char timestr[16];           // Búfer intermedio para formatear el tiempo a cadena de texto
  ip_header *ih;              // Puntero base a la estructura de la cabecera IP
  udp_header *uh;             // Puntero base a la estructura de la cabecera UDP
  u_int ip_len;               // Variable para almacenar el desplazamiento de la cabecera IP
  u_short sport, dport;       // Puertos de red locales en formato de host
  time_t local_tv_sec;        // Segundos de la marca de tiempo de la captura
  string protocolo;           // Protocolo que será asignado

  // Para evitar warnings
  (VOID)(param);

  // Se aumenta número de paquete
  id++;

  // 1. Obtener la hora en que se obtuvo el paquete
  local_tv_sec = header->ts.tv_sec;
  // 2. Restar la hora del paquete menos la hora global de referencia
  // (Asegúrate de que 'hora_global_inicio' esté declarada e inicializada en tu código global)
  time_t tiempo_restado = local_tv_sec - hora_global_inicio;
  gmtime_s(&ltime, &tiempo_restado);
  strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

  // El estándar Ethernet encapsula datos tras 14 bytes. Se saltan 14 bytes para apuntar al inicio de IPv4.
  ih = (ip_header *)(pkt_data + 14);

  // Extrae los 4 bits bajos de 'ver_ihl' para saber el tamaño de la cabecera en palabras de 32 bits, luego multiplica por 4 para obtener bytes
  ip_len = (ih->ver_ihl & 0xf) * 4;

  // Determinar protocolo (17 = UDP, 6 = TCP)
  // Falta añadir el manejo de los distintos protocolos derivados 
  if (ih->proto == 17){
    udp_header *uh = (udp_header *)((u_char*)ih + ip_len);
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);
  } else if (ih->proto == 6){
    tcp_header *th = (tcp_header *)((u_char*)ih + ip_len);
    sport = ntohs(th->sport);
    dport = ntohs(th->dport);
  } else {
    return; 
  }

  // Variables para guardar las direcciones y puertos después de traducir
  char src_ip[32], dst_ip[32];
  char src_puerto[32], dst_puerto[32];

  // Construye la cadena estructurando los 4 bytes individuales de la IP
  sprintf_s(src_ip, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
  sprintf_s(dst_ip, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);

  // Construye los puertos
  sprintf_s(src_puerto, "%d", sport);
  sprintf_s(dst_puerto, "%d", dport);

  // Guardar el vector después de agregar el paquete capturado
  // Se usan las llaves para manejar el uso exclusivo del vector
  {
    // Se bloquea la variable para que este solo la pueda editar
    lock_guard<mutex> lock(paquetes_mutex);

    if (ih->proto == 17){ // UDP
      protocolo=asignar_protocolo(sport, dport, ih->proto);
      PaqueteInfo_UDP nuevo_pkt = {id, timestr, (int)header->len, src_ip, dst_ip, protocolo, src_puerto, dst_puerto};
      lista_paquetes.push_back(nuevo_pkt);
    } else if (ih->proto == 6){  //TCP
      protocolo=asignar_protocolo(sport, dport, ih->proto);
      PaqueteInfo_TCP nuevo_pkt = {id, timestr, (int)header->len, src_ip, dst_ip, protocolo, src_puerto, dst_puerto};
      lista_paquetes.push_back(nuevo_pkt);
    } else {
      return; 
    }
  }
}

void iniciarCaptura(int id_interfaz)
{
  pcap_if_t *alldevs;                 // Puntero base para la enumeración de dispositivos locales
  pcap_if_t *d;                       // Puntero de exploración intermedio
  char errbuf[PCAP_ERRBUF_SIZE];      // Almacenamiento de errores de inicialización
  u_int netmask;                      // Máscara de red de la interfaz elegida (requerido para compilar filtros de pcap)
  char packet_filter[] = "ip and (udp or tcp)";// Filtro de bajo nivel BPF: El sniffer descartará todo tráfico que NO sea IPv4 y UDP y TCP
  struct bpf_program fcode;           // Estructura binaria compilada que almacena la regla del filtro

  // Termina si no encontro las dependencias de npcap
  if (!LoadNpcapDlls()) return;

  // Vuelve a solicitar la lista de interfaces
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) return;
  
  // Buscamos la interfaz que el usuario seleccionó en ImGui
  d = alldevs;
  for (int i = 0; i < id_interfaz && d != NULL; i++) {
      d = d->next;
  }

  // Si no se encuentra termina
  if (d == NULL) {
      pcap_freealldevs(alldevs);
      return;
  }

  // Abre la interfaz en modo promiscuo. 
  // 65536 es la porción máxima del paquete a capturar (Snapshot length). 
  // PCAP_OPENFLAG_PROMISCUOUS fuerza a escuchar TODO el tráfico del segmento físico, no solo lo dirigido a la PC.
  // 500 es el tiempo de Read Timeout en milisegundos.
  if ( (adhandle_global = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 10, NULL, errbuf) ) == NULL) {
    pcap_freealldevs(alldevs);
    return;
  }
  
  // Comprobamos la capa de enlace de datos (Datalink)
  // Solo se soportan redes bajo el estándar Ethernet (DLT_EN10MB).
  if(pcap_datalink(adhandle_global) != DLT_EN10MB) {
    pcap_close(adhandle_global);
    pcap_freealldevs(alldevs);
    return;
  }
  
  // Extrae la máscara de red de la tarjeta seleccionada para inicializar correctamente el motor de filtrado BPF
  if(d->addresses != NULL){
    netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
  }else {
    // Máscara por defecto alternativa (Clase C: 255.255.255.0) en caso de interfaces sin configuración IP
    netmask=0xffffff; 
  }

  // Compila la cadena de texto de filtrado "ip and udp" en código máquina optimizado entendible por el kernel (BPF)
  if (pcap_compile(adhandle_global, &fcode, packet_filter, 1, netmask) < 0 ) {
    pcap_freealldevs(alldevs);
    return;
  }
  
  // Inyecta el filtro compilado directamente en el manejador de captura abierto
  if (pcap_setfilter(adhandle_global, &fcode) < 0) {
    pcap_freealldevs(alldevs);
    return;
  }
  
  // Se liberan todas las otras interfaces que no utilizamos
  pcap_freealldevs(alldevs);
   
  captura_activa = true;
  // Entra en un ciclo infinito controlado por hardware.
  // El segundo parámetro '0' indica que procesará paquetes de forma indefinida hasta que ocurra un error o un pcap_breakloop().
  // Cada vez que llega un paquete, salta automáticamente a ejecutar la función 'packet_handler'.
  hora_global_inicio=time(NULL);
  pcap_loop(adhandle_global, 0, packet_handler, NULL);
}