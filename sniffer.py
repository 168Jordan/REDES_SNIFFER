from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP, IPv6, get_if_list
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from collections import Counter
from datetime import datetime
import argparse
import csv
import sys


parser = argparse.ArgumentParser(description="Packet Sniffer RC-TP2")

CORES = {
    "TCP": "\033[94m",
    "UDP": "\033[92m",
    "DNS": "\033[93m",
    "mDNS": "\033[96m",
    "HTTP": "\033[95m",
    "HTTPS": "\033[35m",
    "FTP": "\033[91m",
    "ARP": "\033[33m",
    "ICMP": "\033[31m",
    "NTP": "\033[36m",
    "DHCP": "\033[34m",
    "IPv4": "\033[37m",
    "IPv6": "\033[90m",
    "?": "\033[2m",
}

RESET = "\033[0m"
BOLD = "\033[1m"

parser.add_argument("-i", "--interface", default="eth0", help="Interface de rede")
parser.add_argument("-c", "--count", type=int, default=0, help="Número de pacotes a capturar")
parser.add_argument("-f", "--filter", default="", help="Filtro BPF")
parser.add_argument("--proto", default="", help="Filtrar por protocolo")
parser.add_argument("--ip", default="", help="Filtrar por IP")
parser.add_argument("--mac", default="", help="Filtrar por MAC")
parser.add_argument("--log", default="", help="Arquivo CSV para salvar os pacotes capturados")

args = parser.parse_args()


PROTOCOLOS_DISPONIVEIS = [
    "TODOS",
    "ARP",
    "IPv4",
    "IPv6",
    "ICMP",
    "TCP",
    "UDP",
    "DNS",
    "mDNS",
    "NTP",
    "DHCP"
]


pacotes_guardados = []
estatisticas = Counter()
total_pacotes = 0
hora_inicio = datetime.now()


def escolher_interface():
    interfaces = get_if_list()

    print("\n=== INTERFACES DISPONÍVEIS ===")
    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. {iface}")

    while True:
        escolha = input("\nEscolhe a interface pelo número: ")

        if escolha.isdigit():
            escolha = int(escolha)
            if 1 <= escolha <= len(interfaces):
                return interfaces[escolha - 1]

        print("Opção inválida. Tenta outra vez.")


def escolher_protocolo():
    print("\n=== PROTOCOLOS DISPONÍVEIS PARA FILTRAR ===")
    for i, proto in enumerate(PROTOCOLOS_DISPONIVEIS, start=1):
        print(f"{i}. {proto}")

    while True:
        escolha = input("\nEscolhe o protocolo pelo número: ")

        if escolha.isdigit():
            escolha = int(escolha)
            if 1 <= escolha <= len(PROTOCOLOS_DISPONIVEIS):
                proto = PROTOCOLOS_DISPONIVEIS[escolha - 1]

                if proto == "TODOS":
                    return ""

                return proto.upper()

        print("Opção inválida. Tenta outra vez.")


def guardar_csv(nome_ficheiro):
    if not nome_ficheiro.endswith(".csv"):
        nome_ficheiro += ".csv"

    with open(nome_ficheiro, "w", newline="", encoding="utf-8") as ficheiro:
        writer = csv.writer(ficheiro)

        writer.writerow([
            "timestamp",
            "interface",
            "tamanho",
            "protocolo",
            "mac_src",
            "mac_dst",
            "ip_src",
            "ip_dst",
            "resumo"
        ])

        writer.writerows(pacotes_guardados)

    print(f"\nCaptura guardada em: {nome_ficheiro}")


if len(sys.argv) == 1:
    args.interface = escolher_interface()
    args.proto = escolher_protocolo()

    print("\nConfiguração escolhida:")
    print(f"Interface : {args.interface}")
    print(f"Protocolo : {args.proto if args.proto else 'TODOS'}")
    print()


def aplicar_filtros(pacote):
    if args.proto:
        proto = args.proto.upper()

        if proto == "ARP" and not pacote.haslayer(ARP):
            return False

        if proto == "IPV4" and not pacote.haslayer(IP):
            return False

        if proto == "IPV6" and not pacote.haslayer(IPv6):
            return False

        if proto == "ICMP" and not pacote.haslayer(ICMP):
            return False

        if proto == "TCP" and not pacote.haslayer(TCP):
            return False

        if proto == "UDP" and not pacote.haslayer(UDP):
            return False

        if proto == "DNS" and not (
            pacote.haslayer(UDP)
            and (pacote[UDP].sport == 53 or pacote[UDP].dport == 53)
        ):
            return False

        if proto == "NTP" and not (
            pacote.haslayer(UDP)
            and (pacote[UDP].sport == 123 or pacote[UDP].dport == 123)
        ):
            return False

        if proto == "DHCP" and not (
            pacote.haslayer(UDP)
            and (
                pacote[UDP].sport in (67, 68)
                or pacote[UDP].dport in (67, 68)
            )
        ):
            return False

        if proto == "MDNS" and not (
            pacote.haslayer(UDP)
            and (pacote[UDP].sport == 5353 or pacote[UDP].dport == 5353)
        ):
            return False

    if args.ip:
        if not pacote.haslayer(IP):
            return False

        if pacote[IP].src != args.ip and pacote[IP].dst != args.ip:
            return False

    if args.mac:
        if not pacote.haslayer(Ether):
            return False

        if pacote[Ether].src != args.mac and pacote[Ether].dst != args.mac:
            return False

    return True


def processar_pacote(pacote):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tamanho = len(pacote)

    protocolo = "?"
    ip_src = ip_dst = "-"
    resumo = "Protocolo desconhecido"

    if pacote.haslayer(Ether):
        mac_src = pacote[Ether].src
        mac_dst = pacote[Ether].dst
    else:
        mac_src = mac_dst = "?"

    if pacote.haslayer(ARP):
        arp = pacote[ARP]
        protocolo = "ARP"

        if arp.op == 1:
            resumo = f"ARP Request: Quem tem {arp.pdst}? Diz a {arp.psrc}"
        else:
            resumo = f"ARP Reply: {arp.psrc} está em {arp.hwsrc}"

    elif pacote.haslayer(IP):
        ip_src = pacote[IP].src
        ip_dst = pacote[IP].dst

        if pacote.haslayer(ICMP):
            icmp = pacote[ICMP]
            protocolo = "ICMP"

            if icmp.type == 8:
                tipo = "Echo Request"
            elif icmp.type == 0:
                tipo = "Echo Reply"
            else:
                tipo = f"Tipo {icmp.type}"

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
                    dominio = pacote[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                    tipo = "Query" if pacote[DNS].qr == 0 else "Reply"
                    resumo = f"DNS {tipo}: {dominio}"
                else:
                    resumo = "DNS"

            elif sport == 5353 or dport == 5353:
                protocolo = "mDNS"

                if pacote.haslayer(DNS) and pacote[DNS].qd:
                    dominio = pacote[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                    resumo = f"mDNS Query: {dominio}"
                else:
                    resumo = "mDNS"

            elif sport in (67, 68) or dport in (67, 68):
                protocolo = "DHCP"

                tipos = {
                    1: "Discover",
                    2: "Offer",
                    3: "Request",
                    5: "ACK",
                    6: "NAK"
                }

                tipo_dhcp = "?"

                if pacote.haslayer(DHCP):
                    for opt in pacote[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "message-type":
                            tipo_dhcp = tipos.get(opt[1], str(opt[1]))
                            break

                resumo = f"DHCP {tipo_dhcp}"

            else:
                protocolo = "UDP"
                resumo = f"UDP :{sport} → :{dport}"

        else:
            protocolo = "IPv4"
            resumo = f"IPv4 protocolo desconhecido ({pacote[IP].proto})"

    elif pacote.haslayer(IPv6):
        ip6 = pacote[IPv6]
        ip_src = ip6.src
        ip_dst = ip6.dst
        protocolo = "IPv6"
        resumo = "IPv6"

    global total_pacotes
    total_pacotes += 1
    estatisticas[protocolo] += 1

    linha_csv = [
        timestamp,
        args.interface,
        tamanho,
        protocolo,
        mac_src,
        mac_dst,
        ip_src,
        ip_dst,
        resumo
    ]

    pacotes_guardados.append(linha_csv)

    cor = CORES.get(protocolo, CORES["?"])

    print(
        f"{cor}{BOLD}[{timestamp}] [{args.interface}] {tamanho:>5}B"
        f" | {protocolo:<8}{RESET}"
        f"{cor}"
        f" | {mac_src} → {mac_dst}"
        f" | {ip_src} → {ip_dst}"
        f" | {resumo}"
        f"{RESET}"
    )


def processar_com_filtro(pacote):
    if aplicar_filtros(pacote):
        processar_pacote(pacote)


try:
    print(f"A capturar em '{args.interface}'")
    sniff(
        iface=args.interface,
        prn=processar_com_filtro,
        count=args.count,
        filter=args.filter,
        store=False
    )

except KeyboardInterrupt:
    print("\nCaptura interrompida pelo utilizador.")

finally:
    hora_fim = datetime.now()
    duracao = hora_fim - hora_inicio

    print("\n" + "=" * 45)
    print(" RESUMO ESTATISTICO DA CAPTURA")
    print("=" * 45)
    print(f" Duracao da captura           : {str(duracao).split('.')[0]}")
    print(f" Total de pacotes processados : {total_pacotes}")
    print("-" * 45)

    if total_pacotes > 0:
        print(" Distribuicao por protocolo:")

        for proto, quantidade in estatisticas.most_common():
            percentagem = (quantidade / total_pacotes) * 100
            cor = CORES.get(proto, CORES["?"])

            print(
                f"  {cor}{BOLD}- {proto:<8}{RESET}"
                f"{cor}: {quantidade:>5} pacotes "
                f"({percentagem:>5.1f}%){RESET}"
            )

    print("=" * 45 + "\n")

    if args.log:
        guardar_csv(args.log)

    elif total_pacotes > 0:
        resposta = input("Queres guardar os resultados num ficheiro CSV? [s/n]: ").strip().lower()

        if resposta in ["s", "sim", "y", "yes"]:
            nome = input("Nome do ficheiro CSV: ").strip()

            if nome == "":
                nome = "captura_sniffer.csv"

            guardar_csv(nome)

        else:
            print("Resultados não foram guardados.")