#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

// Esta é a função "callback" que é chamada SEMPRE que a libpcap apanha um pacote
void processar_pacote(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
    printf("Apanhei um pacote com %d bytes de tamanho!\n", header->len);
    
    // O próximo passo será fazer o cast do 'buffer' para as estruturas dos protocolos
    // struct ether_header *eth = (struct ether_header *)buffer;
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = "wlp2s0"; // Mudar para a vossa interface (ex: eth0, wlan0)

    // 1. Abrir a interface em modo promíscuo (1 = promiscuous mode, 1000 = timeout ms)
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Não foi possível abrir o dispositivo %s: %s\n", device, errbuf);
        return 2;
    }

    printf("A escutar na interface %s...\n", device);

    // 2. Iniciar o loop de captura (apanha 10 pacotes e para. Pôr -1 para infinito)
    pcap_loop(handle, 10, processar_pacote, NULL);

    // 3. Fechar a sessão de captura
    pcap_close(handle);
    printf("\nCaptura terminada.\n");

    return 0;
}