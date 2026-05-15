#include <pcap.h>
#include <iostream>
using namespace std;

//COMPILAR CON CRTL+SHITF+B y DESPUES EJECUTAR EL .exe

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cout<<"Error al buscar dispositivos: \n"<< errbuf;
        return 1;
    }
    cout<<"¡Librería Npcap configurada correctamente!\n";
    pcap_freealldevs(alldevs);
    return 0;
}