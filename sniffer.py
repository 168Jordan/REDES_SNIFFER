from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP, IPv6
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

log_file = None
csv_writer = None
if args.log:
    log_file = open(args.log, "w", newline="", encoding="utf-8")
    csv_writer = csv.writer(log_file)
    csv_writer.writerow(["timestamp", "interface", "tamanho", "mac_src", "mac_dst", "resumo"])


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

    if pacote.haslayer(Ether):
        mac_src = pacote[Ether].src
        mac_dst = pacote[Ether].dst
    else:
        mac_src = mac_dst = "?"

    # ARP
    if pacote.haslayer(ARP):
        arp = pacote[ARP]
        if arp.op == 1:
            resumo = f"ARP Request: Quem tem {arp.pdst}? Diz a {arp.psrc}"
        else:
            resumo = f"ARP Reply: {arp.psrc} está em {arp.hwsrc}"
        print(f"[{timestamp}] [{args.interface}] {tamanho}B | {mac_src} → {mac_dst} | {resumo}")

    # IPv4
    elif pacote.haslayer(IP):
        ip_src = pacote[IP].src
        ip_dst = pacote[IP].dst

        if pacote.haslayer(ICMP):
            icmp = pacote[ICMP]
            tipo = "Echo Request" if icmp.type == 8 else "Echo Reply" if icmp.type == 0 else f"Tipo {icmp.type}"
            resumo = f"ICMP {tipo}: {ip_src} → {ip_dst}"

        elif pacote.haslayer(TCP):
            tcp = pacote[TCP]
            flags = tcp.sprintf("%flags%")
            resumo = f"TCP: {ip_src}:{tcp.sport} → {ip_dst}:{tcp.dport} [{flags}]"

        elif pacote.haslayer(UDP):
            udp = pacote[UDP]
            sport = udp.sport
            dport = udp.dport

            if sport == 123 or dport == 123:
                resumo = f"NTP: {ip_src} → {ip_dst}"
            elif sport == 53 or dport == 53:
                resumo = f"DNS: {ip_src} → {ip_dst}"
            elif sport == 5353 or dport == 5353:
                resumo = f"mDNS: {ip_src} → {ip_dst}"
            elif sport in (67, 68) or dport in (67, 68):
                resumo = f"DHCP: {ip_src} → {ip_dst}"
            else:
                resumo = f"UDP: {ip_src}:{sport} → {ip_dst}:{dport}"

        else:
            resumo = f"IPv4: {ip_src} → {ip_dst} (protocolo desconhecido)"

        print(f"[{timestamp}] [{args.interface}] {tamanho}B | {mac_src} → {mac_dst} | {resumo}")

    elif pacote.haslayer(IPv6):
        ip6 = pacote[IPv6]
        resumo = f"IPv6: {ip6.src} → {ip6.dst}"
        print(f"[{timestamp}] [{args.interface}] {tamanho}B | {mac_src} → {mac_dst} | {resumo}")
    
    else:
        print(f"[{timestamp}] [{args.interface}] {tamanho}B | {mac_src} → {mac_dst} | Protocolo desconhecido")

    if csv_writer:
        csv_writer.writerow([timestamp, args.interface, tamanho, mac_src, mac_dst, resumo])

def processar_com_filtro(pacote):
    if aplicar_filtros(pacote):
        processar_pacote(pacote)

sniff(iface=args.interface, prn=processar_com_filtro, count=args.count, filter=args.filter)

try:
    sniff(iface=args.interface, prn=processar_com_filtro, count=args.count, filter=args.filter)
finally:
    if log_file:
        log_file.close()
        print(f"captura salva em {args.log}")
