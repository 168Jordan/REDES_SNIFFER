from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP, IPv6
from datetime import datetime

def processar_pacote(pacote):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tamanho = len(pacote)

    # Camada Ethernet
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
        print(f"[{timestamp}] {tamanho}B | {mac_src} → {mac_dst} | {resumo}")

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
                resumo = f"NTP: {ip_src} -> {ip_dst}"

            elif sport == 53 or dport == 53:
                resumo = f"DNS: {ip_src} -> {ip_dst}"

            elif sport == 5353 or dport == 5353:
                resumo = f"mDNS: {ip_src} -> {ip_dst}"

            elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
                resumo = f"DHCP: {ip_src} -> {ip_dst}"

            else:
                resumo = f"UDP: {ip_src}:{sport} → {ip_dst}:{dport}"

        else:
            resumo = f"IPv4: {ip_src} → {ip_dst} (protocolo desconhecido)"

        print(f"[{timestamp}] {tamanho}B | {mac_src} → {mac_dst} | {resumo}")

    elif pacote.haslayer(IPv6):
        ip6 = pacote[IPv6]
        resumo = f"IPv6: {ip6.src} → {ip6.dst}"
        print(f"[{timestamp}] {tamanho}B | {mac_src} → {mac_dst} | {resumo}")

    else:
        print(f"[{timestamp}] {tamanho}B | {mac_src} → {mac_dst} | Protocolo desconhecido")

sniff(iface="eth0", prn=processar_pacote, count=10)