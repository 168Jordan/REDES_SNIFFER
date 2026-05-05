from scapy.all import (
    sniff, Ether, ARP, IP, IPv6, ICMP, TCP, UDP,
    Raw, DNS, DNSQR, DNSRR, BOOTP, DHCP, get_if_list
)
from datetime import datetime
from collections import Counter
import argparse
import csv
import json
import os


# Cores ANSI para diferentes protocolos
CORES_PROTOCOLO = {
    "ARP": "\033[96m",      # Ciano
    "IPv4": "\033[92m",     # Verde claro
    "IPv6": "\033[95m",     # Magenta
    "ICMP": "\033[93m",     # Amarelo
    "TCP": "\033[94m",      # Azul
    "UDP": "\033[92m",      # Verde claro
    "DNS": "\033[35m",      # Magenta
    "DHCP": "\033[33m",     # Laranja
    "NTP": "\033[36m",      # Ciano
    "HTTP": "\033[92m",     # Verde claro
    "HTTPS": "\033[34m",    # Azul escuro
    "FTP": "\033[91m",      # Vermelho claro
    "mDNS": "\033[95m",     # Magenta
    "Desconhecido": "\033[37m"  # Branco
}

COR_RESET = "\033[0m"


parser = argparse.ArgumentParser(description="Packet Sniffer RC-TP2")

parser.add_argument("-i", "--interface", default="eth0",
                    help="Interface de rede (ex: eth0, wlo1, wlan0)")

parser.add_argument("-c", "--count", type=int, default=0,
                    help="Número de pacotes a capturar (0 = infinito)")

parser.add_argument("-f", "--filter", default="",
                    help="Filtro BPF (ex: 'tcp', 'host 192.168.1.1', 'port 53')")

parser.add_argument("--proto", default="",
                    help="Filtrar por protocolo: ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, DHCP, NTP, HTTP, HTTPS, FTP")

parser.add_argument("--ip", default="",
                    help="Filtrar por IP de origem ou destino")

parser.add_argument("--mac", default="",
                    help="Filtrar por MAC de origem ou destino")

parser.add_argument("--log", default="",
                    help="Guardar captura em ficheiro: .txt, .csv ou .json")

args = parser.parse_args()


def perguntar_configuracao():
    print("\n========== CONFIGURAÇÃO DO SNIFFER ==========")

    interfaces = get_if_list()

    print("\nInterfaces disponíveis:")
    for i, iface in enumerate(interfaces):
        print(f"{i} - {iface}")

    escolha = input("\nEscolhe a interface pelo número: ").strip()

    if escolha.isdigit() and int(escolha) < len(interfaces):
        args.interface = interfaces[int(escolha)]
    else:
        print("Escolha inválida. A usar a primeira interface disponível.")
        args.interface = interfaces[0]

    count = input("\nQuantos pacotes queres capturar? ").strip()
    if count.isdigit():
        args.count = int(count)
    else:
        args.count = 0

    proto = input(
        "\nProtocolo a filtrar (ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, DHCP, NTP, HTTP, HTTPS, FTP) : "
    ).strip()

    args.proto = proto

    filtro_bpf = input(
        "\nFiltro BPF, ex: tcp, udp, port 53, host 8.8.8.8 : "
    ).strip()

    args.filter = filtro_bpf

    ip = input("\nFiltrar por IP : ").strip()
    args.ip = ip

    mac = input("\nFiltrar por MAC : ").strip()
    args.mac = mac

    guardar_log = input("\nGuardar log? [s/n] : ").strip().lower()
    if guardar_log == "s":
        args.log = input("Nome do ficheiro (ex: captura.csv, captura.json, captura.txt) : ").strip()
    else:
        args.log = ""

    print("\n========== CONFIGURAÇÃO FINAL ==========")
    print(f"Interface: {args.interface}")
    print(f"Pacotes: {'infinito' if args.count == 0 else args.count}")
    print(f"Protocolo: {args.proto if args.proto else 'Todos'}")
    print(f"Filtro BPF: {args.filter if args.filter else 'Nenhum'}")
    print(f"IP: {args.ip if args.ip else 'Nenhum'}")
    print(f"MAC: {args.mac if args.mac else 'Nenhum'}")
    print(f"Log: {args.log if args.log else 'Desativado'}")
    print(f"Mostrar no terminal: Sim")
    print("========================================\n")


perguntar_configuracao()


estatisticas = Counter()
registos_json = []
tempo_inicio = None


def obter_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def obter_macs(pacote):
    if pacote.haslayer(Ether):
        return pacote[Ether].src, pacote[Ether].dst
    return "?", "?"


def obter_ips(pacote):
    if pacote.haslayer(IP):
        return pacote[IP].src, pacote[IP].dst, "IPv4"
    if pacote.haslayer(IPv6):
        return pacote[IPv6].src, pacote[IPv6].dst, "IPv6"
    return "?", "?", "N/A"


def obter_payload_texto(pacote):
    if pacote.haslayer(Raw):
        try:
            return pacote[Raw].load.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""
    return ""


def obter_dhcp_tipo(pacote):
    if not pacote.haslayer(DHCP):
        return "Desconhecido"

    mapa = {
        1: "Discover",
        2: "Offer",
        3: "Request",
        4: "Decline",
        5: "ACK",
        6: "NAK",
        7: "Release",
        8: "Inform"
    }

    for opcao in pacote[DHCP].options:
        if isinstance(opcao, tuple) and opcao[0] == "message-type":
            valor = opcao[1]

            if isinstance(valor, int):
                return mapa.get(valor, f"Tipo {valor}")

            if isinstance(valor, str):
                return valor.capitalize()

    return "Desconhecido"


def obter_dns_info(pacote):
    if not pacote.haslayer(DNS):
        return "DNS"

    dns = pacote[DNS]

    if dns.qr == 0:
        if pacote.haslayer(DNSQR):
            try:
                dominio = pacote[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                dominio = str(pacote[DNSQR].qname)

            return f"DNS Query: domínio={dominio}"

        return "DNS Query"

    else:
        respostas = []

        if dns.ancount > 0:
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if isinstance(rr, DNSRR):
                        respostas.append(str(rr.rdata))
                except Exception:
                    pass

        if respostas:
            return f"DNS Response: respostas={', '.join(respostas[:3])}"

        return "DNS Response"


def obter_http_info(pacote):
    texto = obter_payload_texto(pacote)

    if not texto:
        return ""

    linhas = texto.splitlines()
    primeira = linhas[0] if linhas else texto

    metodos = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

    for metodo in metodos:
        if primeira.startswith(metodo + " "):
            return primeira

    if primeira.startswith("HTTP/"):
        return primeira

    return ""


def obter_ftp_info(pacote):
    texto = obter_payload_texto(pacote)

    if not texto:
        return ""

    linhas = texto.splitlines()
    primeira = linhas[0] if linhas else texto

    comandos = [
        "USER", "PASS", "LIST", "RETR", "STOR", "PWD",
        "CWD", "TYPE", "PASV", "PORT", "QUIT", "SYST", "FEAT"
    ]

    for cmd in comandos:
        if primeira.upper().startswith(cmd):
            return primeira

    if len(primeira) >= 3 and primeira[:3].isdigit():
        return primeira

    return ""


def classificar_tcp_flags(tcp):
    flags = tcp.sprintf("%flags%")

    if flags == "S":
        return "TCP SYN - início de ligação"
    if flags == "SA":
        return "TCP SYN-ACK - resposta ao pedido de ligação"
    if flags == "A":
        return "TCP ACK - confirmação"
    if "F" in flags:
        return "TCP FIN - terminação de ligação"
    if "R" in flags:
        return "TCP RST - ligação reiniciada"
    if "P" in flags and "A" in flags:
        return "TCP PSH-ACK - envio de dados"

    return f"TCP flags={flags}"


def identificar_pacote(pacote):
    timestamp = obter_timestamp()
    tamanho = len(pacote)
    mac_src, mac_dst = obter_macs(pacote)
    ip_src, ip_dst, versao_ip = obter_ips(pacote)

    protocolo = "Desconhecido"
    resumo = "Protocolo desconhecido"
    portas = ""

    if pacote.haslayer(ARP):
        arp = pacote[ARP]
        protocolo = "ARP"

        if arp.op == 1:
            resumo = f"ARP Request: Quem tem {arp.pdst}? Diz a {arp.psrc}"
        elif arp.op == 2:
            resumo = f"ARP Reply: {arp.psrc} está em {arp.hwsrc}"
        else:
            resumo = f"ARP operação={arp.op}"

    elif pacote.haslayer(IP) or pacote.haslayer(IPv6):

        if pacote.haslayer(ICMP):
            icmp = pacote[ICMP]
            protocolo = "ICMP"

            if icmp.type == 8:
                resumo = f"ICMP Echo Request: {ip_src} → {ip_dst}"
            elif icmp.type == 0:
                resumo = f"ICMP Echo Reply: {ip_src} → {ip_dst}"
            else:
                resumo = f"ICMP tipo={icmp.type}: {ip_src} → {ip_dst}"

        elif pacote.haslayer(TCP):
            tcp = pacote[TCP]
            sport = tcp.sport
            dport = tcp.dport
            portas = f"{sport} → {dport}"

            flags_info = classificar_tcp_flags(tcp)

            if sport == 80 or dport == 80:
                protocolo = "HTTP"
                http_info = obter_http_info(pacote)

                if http_info:
                    resumo = f"HTTP: {ip_src}:{sport} → {ip_dst}:{dport} | {http_info}"
                else:
                    resumo = f"HTTP: {ip_src}:{sport} → {ip_dst}:{dport} | {flags_info}"

            elif sport == 443 or dport == 443:
                protocolo = "HTTPS"
                resumo = f"HTTPS: {ip_src}:{sport} → {ip_dst}:{dport} | tráfego cifrado | {flags_info}"

            elif sport == 21 or dport == 21:
                protocolo = "FTP"
                ftp_info = obter_ftp_info(pacote)

                if ftp_info:
                    resumo = f"FTP: {ip_src}:{sport} → {ip_dst}:{dport} | {ftp_info}"
                else:
                    resumo = f"FTP: {ip_src}:{sport} → {ip_dst}:{dport} | {flags_info}"

            else:
                protocolo = "TCP"
                resumo = f"TCP: {ip_src}:{sport} → {ip_dst}:{dport} | {flags_info}"

        elif pacote.haslayer(UDP):
            udp = pacote[UDP]
            sport = udp.sport
            dport = udp.dport
            portas = f"{sport} → {dport}"

            if pacote.haslayer(BOOTP) and pacote.haslayer(DHCP):
                protocolo = "DHCP"
                tipo = obter_dhcp_tipo(pacote)
                xid = pacote[BOOTP].xid
                resumo = f"DHCP {tipo}: {ip_src}:{sport} → {ip_dst}:{dport} | xid={xid}"

            elif pacote.haslayer(DNS) or sport == 53 or dport == 53:
                protocolo = "DNS"
                dns_info = obter_dns_info(pacote)
                resumo = f"{dns_info}: {ip_src}:{sport} → {ip_dst}:{dport}"

            elif sport == 123 or dport == 123:
                protocolo = "NTP"
                resumo = f"NTP: {ip_src}:{sport} → {ip_dst}:{dport} | sincronização temporal"

            elif sport == 5353 or dport == 5353:
                protocolo = "mDNS"
                resumo = f"mDNS: {ip_src}:{sport} → {ip_dst}:{dport} | DNS multicast local"

            else:
                protocolo = "UDP"
                resumo = f"UDP: {ip_src}:{sport} → {ip_dst}:{dport}"

        else:
            protocolo = versao_ip
            resumo = f"{versao_ip}: {ip_src} → {ip_dst}"

    registo = {
        "timestamp": timestamp,
        "interface": args.interface,
        "protocolo": protocolo,
        "mac_src": mac_src,
        "mac_dst": mac_dst,
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "portas": portas,
        "tamanho": tamanho,
        "resumo": resumo
    }

    return registo


def aplicar_filtros(pacote):
    if args.proto:
        proto = args.proto.upper()

        registo_temp = identificar_pacote(pacote)

        if registo_temp["protocolo"].upper() != proto:
            if proto == "IPv4" and pacote.haslayer(IP):
                pass
            elif proto == "IPv6" and pacote.haslayer(IPv6):
                pass
            else:
                return False

    if args.ip:
        if pacote.haslayer(IP):
            if pacote[IP].src != args.ip and pacote[IP].dst != args.ip:
                return False
        elif pacote.haslayer(IPv6):
            if pacote[IPv6].src != args.ip and pacote[IPv6].dst != args.ip:
                return False
        else:
            return False

    if args.mac:
        if not pacote.haslayer(Ether):
            return False

        mac_filtro = args.mac.lower()

        if pacote[Ether].src.lower() != mac_filtro and pacote[Ether].dst.lower() != mac_filtro:
            return False

    return True


def linha_formatada(registo):
    protocolo = registo['protocolo']
    cor = CORES_PROTOCOLO.get(protocolo, CORES_PROTOCOLO["Desconhecido"])
    
    return (
        f"{cor}[{registo['timestamp']}] "
        f"[{registo['interface']}] "
        f"{registo['tamanho']}B | "
        f"{registo['protocolo']} | "
        f"{registo['mac_src']} → {registo['mac_dst']} | "
        f"{registo['resumo']}{COR_RESET}"
    )


def iniciar_log_csv():
    if not args.log:
        return

    if args.log.endswith(".csv"):
        ficheiro_existe = os.path.exists(args.log)

        with open(args.log, "a", newline="", encoding="utf-8") as f:
            campos = [
                "timestamp", "interface", "protocolo",
                "mac_src", "mac_dst",
                "ip_src", "ip_dst",
                "portas", "tamanho", "resumo"
            ]

            writer = csv.DictWriter(f, fieldnames=campos)

            if not ficheiro_existe:
                writer.writeheader()


def guardar_log(registo):
    if not args.log:
        return

    if args.log.endswith(".csv"):
        with open(args.log, "a", newline="", encoding="utf-8") as f:
            campos = [
                "timestamp", "interface", "protocolo",
                "mac_src", "mac_dst",
                "ip_src", "ip_dst",
                "portas", "tamanho", "resumo"
            ]

            writer = csv.DictWriter(f, fieldnames=campos)
            writer.writerow(registo)

    elif args.log.endswith(".json"):
        registos_json.append(registo)

    else:
        with open(args.log, "a", encoding="utf-8") as f:
            f.write(linha_formatada(registo) + "\n")


def guardar_json_final():
    if args.log and args.log.endswith(".json"):
        with open(args.log, "w", encoding="utf-8") as f:
            json.dump(registos_json, f, indent=4, ensure_ascii=False)


def processar_pacote(pacote):
    if not aplicar_filtros(pacote):
        return

    registo = identificar_pacote(pacote)

    estatisticas[registo["protocolo"]] += 1

    print(linha_formatada(registo))
    guardar_log(registo)


def mostrar_resumo_final():
    print("\n========== RESUMO ESTATÍSTICO DA CAPTURA ==========")
    print(f"Interface: {args.interface}")
    
    total_pacotes = sum(estatisticas.values())
    print(f"Total de pacotes processados: {total_pacotes}")
    
    if tempo_inicio:
        tempo_decorrido = datetime.now() - tempo_inicio
        segundos = tempo_decorrido.total_seconds()
        minutos = segundos // 60
        segundos = segundos % 60
        print(f"Tempo de captura: {int(minutos)}m {int(segundos)}s")

    print("\nDistribuição por protocolo:")
    for protocolo, quantidade in estatisticas.most_common():
        percentagem = (quantidade / total_pacotes * 100) if total_pacotes > 0 else 0
        print(f"  {protocolo}: {quantidade} ({percentagem:.1f}%)")

    print("===================================================")


def main():
    global tempo_inicio
    
    tempo_inicio = datetime.now()
    iniciar_log_csv()

    print("========== Packet Sniffer RC-TP2 ==========")
    print(f"Interface: {args.interface}")
    print(f"Filtro BPF: {args.filter if args.filter else 'Nenhum'}")
    print(f"Filtro protocolo: {args.proto if args.proto else 'Nenhum'}")
    print(f"Filtro IP: {args.ip if args.ip else 'Nenhum'}")
    print(f"Filtro MAC: {args.mac if args.mac else 'Nenhum'}")
    print(f"Log: {args.log if args.log else 'Desativado'}")
    print("A capturar... usa CTRL+C para parar.")
    print("===========================================\n")

    try:
        sniff(
            iface=args.interface,
            prn=processar_pacote,
            count=args.count,
            filter=args.filter,
            store=False
        )

    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo utilizador.")

    except PermissionError:
        print("\nErro: sem permissões.")
        print("Experimenta correr com sudo:")
        print(f"sudo python3 sniffer.py -i {args.interface}")

    except Exception as e:
        print(f"\nErro durante a captura: {e}")

    finally:
        guardar_json_final()
        mostrar_resumo_final()


if __name__ == "__main__":
    main()