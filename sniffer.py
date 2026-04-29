from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP, IPv6
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from collections import Counter
from datetime import datetime
import argparse
import csv  


parser = argparse.ArgumentParser(description="Packet Sniffer RC-TP2")
parser.add_argument("-i", "--interface", default="eth0", help="Interface de rede (ex: eth0, wlan0)")
parser.add_argument("-c", "--count", type=int, default=0, help="Número de pacotes a capturar (0 = infinito)")
parser.add_argument("-f", "--filter", default="", help="Filtro BPF (ex: 'tcp', 'host 192.168.1.1')")
parser.add_argument("--proto", default="", help="Filtrar por protocolo (ARP, ICMP, TCP, UDP, DNS, NTP)")
parser.add_argument("--ip", default="", help="Filtrar por IP (origem ou destino)")
parser.add_argument("--mac", default="", help="Filtrar por MAC (origem ou destino)")
parser.add_argument("--log", default="", help="Arquivo CSV para salvar os pacotes capturados")
args = parser.parse_args()



#cenas para resumo final
estatisticas = Counter()
total_pacotes = 0
hora_inicio = datetime.now()




log_file = None
csv_writer = None
if args.log:
    log_file = open(args.log, "w", newline="", encoding="utf-8")
    csv_writer = csv.writer(log_file)
    csv_writer.writerow(["timestamp", "interface", "tamanho","protocolo", "mac_src", "mac_dst","ip_src", "ip_dst", "resumo"])


def aplicar_filtros(pacote):
    #filtro por protocolo
    if args.proto:
        proto = args.proto.upper()
        if proto == "ARP" and not pacote.haslayer(ARP): return False
        if proto == "ICMP" and not pacote.haslayer(ICMP): return False
        if proto == "TCP" and not pacote.haslayer(TCP): return False
        if proto == "UDP" and not pacote.haslayer(UDP): return False
        if proto == "DNS" and not (pacote.haslayer(UDP) and (pacote[UDP].sport == 53 or pacote[UDP].dport == 53)): return False
        if proto == "NTP" and not (pacote.haslayer(UDP) and (pacote[UDP].sport == 123 or pacote[UDP].dport == 123)): return False
        if proto == "DHCP" and not (pacote.haslayer(UDP) and (pacote[UDP].sport in (67, 68) or pacote[UDP].dport in (67, 68))): return False
        if proto == "MDNS" and not (pacote.haslayer(UDP) and (pacote[UDP].sport == 5353 or pacote[UDP].dport == 5353)): return False


    #filtro por IP
    if args.ip:
        if not pacote.haslayer(IP): return False
        if pacote[IP].src != args.ip and pacote[IP].dst != args.ip: return False


    #filtro por MAC
    if args.mac:
        if not pacote.haslayer(Ether): return False
        if pacote[Ether].src != args.mac and pacote[Ether].dst != args.mac: return False

    return True


def processar_pacote(pacote):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tamanho = len(pacote)

    protocolo ="?"
    ip_src = ip_dst = "-"
    resumo = "Protocolo desconhecido"

    if pacote.haslayer(Ether):
        mac_src = pacote[Ether].src
        mac_dst = pacote[Ether].dst
    else:
        mac_src = mac_dst = "?"

    # ARP
    if pacote.haslayer(ARP):
        arp = pacote[ARP]
        protocolo = "ARP"
        if arp.op == 1:
            resumo = f"ARP Request: Quem tem {arp.pdst}? Diz a {arp.psrc}"
        else:
            resumo = f"ARP Reply: {arp.psrc} está em {arp.hwsrc}"

    # IPv4
    elif pacote.haslayer(IP):
        ip_src = pacote[IP].src
        ip_dst = pacote[IP].dst

        if pacote.haslayer(ICMP):
            icmp = pacote[ICMP]
            protocolo = "ICMP"
            tipo = "Echo Request" if icmp.type == 8 else "Echo Reply" if icmp.type == 0 else f"Tipo {icmp.type}"
            resumo = f"ICMP {tipo}: {ip_src} → {ip_dst}"

        elif pacote.haslayer(TCP):
            tcp = pacote[TCP]
            protocolo = "TCP"
            flags = tcp.sprintf("%flags%")
            if "S" in flags and "A" not in flags:
                descricao = "SYN - início handshake"
            elif "S" in flags and "A" in flags:
                descricao = "SYN-ACK - resposta handshake"
            elif "F" in flags:
                descricao = "FIN - início fecho"
            elif "R" in flags:
                descricao = "RST - reset"
            else:
                descricao = flags

            sport = tcp.sport
            dport = tcp.dport

            if sport == 80 or dport == 80:
                protocolo = "HTTP"
                resumo = f"HTTP :{sport} → :{dport}"
            elif sport == 443 or dport == 443:
                protocolo = "HTTPS"
                resumo = f"HTTPS :{sport} → :{dport}"
            elif sport == 21 or dport == 21:
                protocolo = "FTP"
                resumo = f"FTP :{sport} → :{dport}"

            else:
                resumo = f"TCP {descricao} :{sport} → :{dport}"



        elif pacote.haslayer(UDP):
            udp = pacote[UDP]
            sport = udp.sport
            dport = udp.dport

            if sport == 123 or dport == 123:
                protocolo = "NTP"
                resumo = "NTP sync"


            elif sport == 53 or dport == 53:
                protocolo = "DNS"
                if pacote.haslayer(DNS) and pacote[DNS].qd:
                    dominio = pacote[DNS].qd.qname.decode().rstrip(".")
                    tipo = "Query" if pacote[DNS].qr == 0 else "Reply"
                    resumo = f"DNS{tipo}: {dominio}"
                else:
                    resumo = "DNS"


            elif sport == 5353 or dport == 5353:
                protocolo = "mDNS"
                if pacote.haslayer(DNS) and pacote[DNS].qd:
                    dominio = pacote[DNS].qd.qname.decode().rstrip(".")
                    resumo  = f"mDNS Query: {dominio}"
                else:
                    resumo = "mDNS"


            elif sport in (67, 68) or dport in (67, 68):
                protocolo = "DHCP"
                from scapy.layers.dhcp import DHCP
                tipos = {1: "Discover", 2: "Offer", 3: "Request", 5: "ACK", 6: "NAK"}
                tipo_dhcp = "?"
                if pacote.haslayer(DHCP):
                    for opt in pacote[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "message-type":
                            tipo_dhcp = tipos.get(opt[1], str(opt[1]))
                            break
                resumo = f"DHCP {tipo_dhcp}"


            else:
                protocolo = "UDP"
                resumo    = f"UDP :{sport} → :{dport}"

        else:
            protocolo = "IPv4"
            resumo = f"IPv4 (protocolo desconhecido) ({pacote[IP].proto})"


    elif pacote.haslayer(IPv6):
        ip6 = pacote[IPv6]
        ip_src = ip6.src
        ip_dst = ip6.dst
        protocolo = "IPv6"
        resumo = "IPv6"


    global total_pacotes
    total_pacotes += 1
    estatisticas[protocolo] += 1




    print(
            f"[{timestamp}] [{args.interface}] {tamanho:>5}B"
            f" | {protocolo:<8}"
            f" | {mac_src} → {mac_dst}"
            f" | {ip_src} → {ip_dst}"
            f" | {resumo}"
        )


    if csv_writer:
        csv_writer.writerow([timestamp, args.interface, tamanho, protocolo, mac_src, mac_dst, ip_src, ip_dst, resumo])

def processar_com_filtro(pacote):
    if aplicar_filtros(pacote):
        processar_pacote(pacote)

try:
    print(f"A capturar em '{args.interface}'")
    sniff(iface=args.interface, prn=processar_com_filtro, count=args.count, filter=args.filter, store=False)

except KeyboardInterrupt:
    print("\nCaptura interrompida pelo utilizador.")
    
finally:
    if log_file:
        log_file.close()
        print(f"Captura guardada em {args.log}")
        
    # --- RELATORIO FINAL ESTATISTICO ---
    hora_fim = datetime.now()
    duracao = hora_fim - hora_inicio
    
    print("\n" + "="*45)
    print(" RESUMO ESTATISTICO DA CAPTURA")
    print("="*45)
    print(f" Duracao da captura           : {str(duracao).split('.')[0]}")
    print(f" Total de pacotes processados : {total_pacotes}")
    print("-" * 45)
    
    if total_pacotes > 0:
        print(" Distribuicao por protocolo:")
        for proto, quantidade in estatisticas.most_common():
            percentagem = (quantidade / total_pacotes) * 100
            print(f"  - {proto:<8}: {quantidade:>5} pacotes ({percentagem:>5.1f}%)")
    print("="*45 + "\n")