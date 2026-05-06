from scapy.all import (
    sniff, Ether, ARP, IP, IPv6, ICMP, TCP, UDP,
    Raw, DNS, DNSQR, DNSRR, get_if_list
)
from datetime import datetime
from collections import Counter
import argparse
import csv
import json
import os


# ==========================================
# CORES ANSI PARA O TERMINAL
# ==========================================
CORES_PROTOCOLO = {
    "ARP": "\033[96m",      # Ciano
    "IPv4": "\033[92m",     # Verde claro
    "IPv6": "\033[95m",     # Magenta
    "ICMP": "\033[93m",     # Amarelo
    "TCP": "\033[94m",      # Azul
    "UDP": "\033[92m",      # Verde claro
    "DNS": "\033[35m",      # Magenta
    "HTTP": "\033[92m",     # Verde claro
    "HTTPS": "\033[34m",    # Azul escuro
    "Desconhecido": "\033[37m"  # Branco
}
COR_RESET = "\033[0m"


# ==========================================
# ARGUMENTOS DA LINHA DE COMANDOS
# ==========================================
parser = argparse.ArgumentParser(description="Packet Sniffer RC-TP2")

parser.add_argument("-i", "--interface", default="eth0",
                    help="Interface de rede (ex: eth0, wlo1, wlan0)")
parser.add_argument("-c", "--count", type=int, default=0,
                    help="Número de pacotes a capturar (0 = infinito)")
parser.add_argument("-f", "--filter", default="",
                    help="Filtro BPF (ex: 'tcp', 'host 192.168.1.1', 'port 53')")
parser.add_argument("--proto", default="",
                    help="Filtrar por protocolo: ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, HTTP, HTTPS")
parser.add_argument("--ip", default="",
                    help="Filtrar por IP de origem ou destino")
parser.add_argument("--mac", default="",
                    help="Filtrar por MAC de origem ou destino")
parser.add_argument("--log", default="",
                    help="Guardar captura em ficheiro: .txt, .csv ou .json")

args = parser.parse_args()


# ==========================================
# MENU INTERATIVO
# ==========================================
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
        args.interface = interfaces[0] if interfaces else "eth0"

    count = input("\nQuantos pacotes queres capturar? [0 para infinito]: ").strip()
    args.count = int(count) if count.isdigit() else 0

    proto = input("\nProtocolo a filtrar (ex: ARP, ICMP, TCP, DNS) [Enter para todos]: ").strip()
    args.proto = proto

    filtro_bpf = input("\nFiltro BPF (ex: tcp, udp, port 53) [Enter para nenhum]: ").strip()
    args.filter = filtro_bpf

    ip = input("\nFiltrar por IP [Enter para nenhum]: ").strip()
    args.ip = ip

    mac = input("\nFiltrar por MAC [Enter para nenhum]: ").strip()
    args.mac = mac

    guardar_log = input("\nGuardar log? [s/n]: ").strip().lower()
    if guardar_log == "s":
        args.log = input("Nome do ficheiro (ex: captura.csv, captura.json): ").strip()
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
    print("========================================\n")


# Se o utilizador não passar nenhum argumento além dos padrões, chama o menu
argumentos_passados = any([args.filter, args.proto, args.ip, args.mac, args.log, args.count > 0, args.interface != "eth0"])
if not argumentos_passados:
    perguntar_configuracao()


# ==========================================
# VARIÁVEIS GLOBAIS DE ESTADO E MEMÓRIA
# ==========================================
estatisticas_camadas = {
    "Camada 2 (Ligação de Dados)": Counter(),
    "Camada 3 (Rede)": Counter(),
    "Camada 4 (Transporte)": Counter(),
    "Camada 7 (Aplicação)": Counter()
}
total_processados = 0
registos_json = []
tempo_inicio = None
pacotes_validados = 0

# Variáveis para o Rastreamento de Estado (State Tracking)
contador_pacotes = 0
memoria_pedidos = {}


# ==========================================
# FUNÇÕES DE EXTRAÇÃO DE DADOS
# ==========================================
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

def obter_hierarquia(pacote, protocolo_final):
    camadas = ["Ethernet"]
    
    if pacote.haslayer(IP): 
        camadas.append("IPv4")
    elif pacote.haslayer(IPv6): 
        camadas.append("IPv6")
        
    if pacote.haslayer(TCP): 
        camadas.append("TCP")
    elif pacote.haslayer(UDP): 
        camadas.append("UDP")
    elif pacote.haslayer(ICMP): 
        camadas.append("ICMP")
        
    if protocolo_final not in camadas and protocolo_final not in ["IPv4", "IPv6", "Desconhecido"]:
        camadas.append(protocolo_final)
        
    return "/".join(camadas)

def obter_payload_texto(pacote):
    if pacote.haslayer(Raw):
        try:
            return pacote[Raw].load.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""
    return ""

def obter_dns_info(pacote):
    if not pacote.haslayer(DNS): return "DNS"
    dns = pacote[DNS]
    if dns.qr == 0:
        if pacote.haslayer(DNSQR):
            try: dominio = pacote[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception: dominio = str(pacote[DNSQR].qname)
            return f"DNS Query: domínio={dominio}"
        return "DNS Query"
    else:
        respostas = []
        if dns.ancount > 0:
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if isinstance(rr, DNSRR): respostas.append(str(rr.rdata))
                except Exception: pass
        if respostas: return f"DNS Response: respostas={', '.join(respostas[:3])}"
        return "DNS Response"

def obter_http_info(pacote):
    texto = obter_payload_texto(pacote)
    if not texto: return ""
    linhas = texto.splitlines()
    primeira = linhas[0] if linhas else texto
    metodos = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    for metodo in metodos:
        if primeira.startswith(metodo + " "): return primeira
    if primeira.startswith("HTTP/"): return primeira
    return ""

def classificar_tcp_flags(tcp):
    flags = tcp.sprintf("%flags%")
    if flags == "S": return "TCP SYN - início de ligação"
    if flags == "SA": return "TCP SYN-ACK - resposta ao pedido"
    if flags == "A": return "TCP ACK - confirmação"
    if "F" in flags: return "TCP FIN - terminação de ligação"
    if "R" in flags: return "TCP RST - ligação reiniciada"
    if "P" in flags and "A" in flags: return "TCP PSH-ACK - envio de dados"
    return f"TCP flags={flags}"


# ==========================================
# MOTOR PRINCIPAL DE IDENTIFICAÇÃO E TRACKING
# ==========================================
def identificar_pacote(pacote):
    global contador_pacotes, memoria_pedidos
    contador_pacotes += 1
    id_pacote = contador_pacotes
    ref_pacote = "" 

    timestamp = obter_timestamp()
    tamanho = len(pacote)
    mac_src, mac_dst = obter_macs(pacote)
    ip_src, ip_dst, versao_ip = obter_ips(pacote)

    protocolo = "Desconhecido"
    resumo = "Protocolo desconhecido"
    portas = ""
    ttl = "-"
    ip_len = str(tamanho)

    # Extrair TTL e IP Length
    if pacote.haslayer(IP):
        ttl = str(pacote[IP].ttl)
        ip_len = str(pacote[IP].len)
    elif pacote.haslayer(IPv6):
        ttl = str(pacote[IPv6].hlim)
        ip_len = str(pacote[IPv6].plen)

    # =============== CAMADA 2: ARP ===============
    if pacote.haslayer(ARP):
        arp = pacote[ARP]
        protocolo = "ARP"

        mac_src = "?"
        mac_dst = "?"

        ip_src = arp.psrc
        ip_dst = arp.pdst

        if arp.op == 1:
            resumo = f"ARP Request: Quem tem {arp.pdst}? Diz a {arp.psrc}"
            memoria_pedidos[("ARP", arp.pdst)] = id_pacote 
            
        elif arp.op == 2:
            resumo = f"ARP Reply: {arp.psrc} está em {arp.hwsrc}"
            ref = memoria_pedidos.pop(("ARP", arp.psrc), None) 
            if ref:
                ref_pacote = ref
                resumo += f" [Resposta ao #{ref}]"
        else:
            resumo = f"ARP operação={arp.op}"

    # =============== CAMADA 3: IP/IPv6 ===============
    elif pacote.haslayer(IP) or pacote.haslayer(IPv6):

        if pacote.haslayer(ICMP):
            icmp = pacote[ICMP]
            protocolo = "ICMP"

            if icmp.type == 8:
                resumo = f"ICMP Echo Request: {ip_src} → {ip_dst}"
                chave = ("ICMP", ip_src, ip_dst, icmp.id, icmp.seq)
                memoria_pedidos[chave] = id_pacote 
                
            elif icmp.type == 0:
                resumo = f"ICMP Echo Reply: {ip_src} → {ip_dst}"
                chave_inversa = ("ICMP", ip_dst, ip_src, icmp.id, icmp.seq)
                ref = memoria_pedidos.pop(chave_inversa, None) 
                if ref:
                    ref_pacote = ref
                    resumo += f" [Resposta ao #{ref}]"
            else:
                resumo = f"ICMP tipo={icmp.type}: {ip_src} → {ip_dst}"

        # =============== CAMADA 4: TCP ===============
        elif pacote.haslayer(TCP):
            tcp = pacote[TCP]
            sport = tcp.sport
            dport = tcp.dport
            portas = f"{sport} → {dport}"

            flags_info = classificar_tcp_flags(tcp)

            if sport == 80 or dport == 80:
                protocolo = "HTTP"
                http_info = obter_http_info(pacote)
                resumo = f"HTTP: {ip_src}:{sport} → {ip_dst}:{dport} | {http_info if http_info else flags_info}"

            elif sport == 443 or dport == 443:
                protocolo = "HTTPS"
                resumo = f"HTTPS: {ip_src}:{sport} → {ip_dst}:{dport} | tráfego cifrado | {flags_info}"

            else:
                protocolo = "TCP"
                resumo = f"TCP: {ip_src}:{sport} → {ip_dst}:{dport} | {flags_info}"

        # =============== CAMADA 4: UDP ===============
        elif pacote.haslayer(UDP):
            udp = pacote[UDP]
            sport = udp.sport
            dport = udp.dport
            portas = f"{sport} → {dport}"

            if pacote.haslayer(DNS) or sport == 53 or dport == 53:
                protocolo = "DNS"
                dns_info = obter_dns_info(pacote)
                
                # Tracking DNS
                if pacote.haslayer(DNS):
                    dns = pacote[DNS]
                    if dns.qr == 0:
                        memoria_pedidos[("DNS", dns.id)] = id_pacote
                    elif dns.qr == 1:
                        ref = memoria_pedidos.pop(("DNS", dns.id), None)
                        if ref:
                            ref_pacote = ref
                            dns_info += f" [Resposta ao #{ref}]"

                resumo = f"{dns_info}: {ip_src}:{sport} → {ip_dst}:{dport}"

            else:
                protocolo = "UDP"
                resumo = f"UDP: {ip_src}:{sport} → {ip_dst}:{dport}"

        else:
            protocolo = versao_ip
            resumo = f"{versao_ip}: {ip_src} → {ip_dst}"

    hierarquia = obter_hierarquia(pacote, protocolo)

    registo = {
        "id_pacote": id_pacote,
        "ref_pacote": ref_pacote,
        "timestamp": timestamp,
        "interface": args.interface,
        "protocolo": protocolo,
        "hierarquia": hierarquia,
        "ttl": ttl,
        "ip_len": ip_len,
        "mac_src": mac_src,
        "mac_dst": mac_dst,
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "portas": portas,
        "tamanho": tamanho,
        "resumo": resumo
    }

    return registo


# ==========================================
# FILTROS E EXIBIÇÃO
# ==========================================
def aplicar_filtros(pacote):
    if args.proto:
        proto = args.proto.upper()
        registo_temp = identificar_pacote(pacote)
        
        global contador_pacotes
        contador_pacotes -= 1 

        if registo_temp["protocolo"].upper() != proto:
            if proto == "IPV4" and pacote.haslayer(IP): pass
            elif proto == "IPV6" and pacote.haslayer(IPv6): pass
            else: return False

    if args.ip:
        if pacote.haslayer(IP):
            if pacote[IP].src != args.ip and pacote[IP].dst != args.ip: return False
        elif pacote.haslayer(IPv6):
            if pacote[IPv6].src != args.ip and pacote[IPv6].dst != args.ip: return False
        else: return False

    if args.mac:
        if not pacote.haslayer(Ether): return False
        mac_filtro = args.mac.lower()
        if pacote[Ether].src.lower() != mac_filtro and pacote[Ether].dst.lower() != mac_filtro: return False

    return True


def linha_formatada(registo):
    protocolo = registo['protocolo']
    cor = CORES_PROTOCOLO.get(protocolo, CORES_PROTOCOLO["Desconhecido"])
    
    return (
        f"{cor}[#{registo['id_pacote']:<4}] [{registo['timestamp']}] "
        f"Len:{registo['ip_len']:<4} TTL:{registo['ttl']:<3} | "
        f"{registo['hierarquia']:<26} | "
        f"MAC: {registo['mac_src']} → {registo['mac_dst']} | "
        f"IP: {registo['ip_src']} → {registo['ip_dst']} | "
        f"{registo['resumo']}{COR_RESET}"
    )


# ==========================================
# LOGGING (CSV / JSON / TXT)
# ==========================================
def iniciar_log_csv():
    if not args.log: return
    if args.log.endswith(".csv"):
        ficheiro_existe = os.path.exists(args.log)
        with open(args.log, "a", newline="", encoding="utf-8") as f:
            campos = [
                "id_pacote", "ref_pacote", "timestamp", "interface", "protocolo",
                "hierarquia", "ttl", "ip_len", "mac_src", "mac_dst",
                "ip_src", "ip_dst", "portas", "tamanho", "resumo"
            ]
            writer = csv.DictWriter(f, fieldnames=campos)
            if not ficheiro_existe:
                writer.writeheader()

def guardar_log(registo):
    if not args.log: return
    if args.log.endswith(".csv"):
        with open(args.log, "a", newline="", encoding="utf-8") as f:
            campos = [
                "id_pacote", "ref_pacote", "timestamp", "interface", "protocolo",
                "hierarquia", "ttl", "ip_len", "mac_src", "mac_dst",
                "ip_src", "ip_dst", "portas", "tamanho", "resumo"
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


# ==========================================
# CALLBACK E ENCERRAMENTO
# ==========================================
def processar_pacote(pacote):    
    if not aplicar_filtros(pacote):
        return

    global total_processados
    total_processados += 1

    registo = identificar_pacote(pacote)

    # === DISTRIBUIÇÃO ESTATÍSTICA PELO MODELO OSI ===
    camadas_presentes = registo["hierarquia"].split("/")
    for c in camadas_presentes:
        if c in ["Ethernet"]: 
            estatisticas_camadas["Camada 2 (Ligação de Dados)"][c] += 1
        elif c in ["IPv4", "IPv6", "ARP", "ICMP"]: 
            estatisticas_camadas["Camada 3 (Rede)"][c] += 1
        elif c in ["TCP", "UDP"]: 
            estatisticas_camadas["Camada 4 (Transporte)"][c] += 1
        elif c not in ["Desconhecido", ""]: 
            estatisticas_camadas["Camada 7 (Aplicação)"][c] += 1

    print(linha_formatada(registo))
    guardar_log(registo)

def parar_captura(pacote):
    if args.count > 0 and total_processados >= args.count:
        return True
    return False

def mostrar_resumo_final():
    COR_TITULO = "\033[1;36m"
    COR_INFO = "\033[1;37m"

    print(f"\n{COR_TITULO}========== RESUMO ESTATÍSTICO DA CAPTURA =========={COR_RESET}")
    print(f"Interface: {COR_INFO}{args.interface}{COR_RESET}")
    
    global total_processados
    print(f"Total de pacotes validados e processados: {COR_INFO}{total_processados}{COR_RESET}")
    
    if tempo_inicio:
        tempo_decorrido = datetime.now() - tempo_inicio
        segundos = tempo_decorrido.total_seconds()
        minutos = segundos // 60
        segundos = segundos % 60
        print(f"Tempo de captura: {COR_INFO}{int(minutos)}m {int(segundos)}s{COR_RESET}")

    print(f"\n{COR_TITULO}Distribuição de Tráfego por Camadas OSI:{COR_RESET}")
    for nome_camada, contador in estatisticas_camadas.items():
        if sum(contador.values()) > 0:  
            print(f"\n{COR_INFO}[{nome_camada}]{COR_RESET}")
            for protocolo, quantidade in contador.most_common():
                percentagem = (quantidade / total_processados * 100) if total_processados > 0 else 0
                cor_proto = CORES_PROTOCOLO.get(protocolo, CORES_PROTOCOLO["Desconhecido"])
                print(f"  > {cor_proto}{protocolo:<7}{COR_RESET}: {quantidade:<4} ({percentagem:.1f}%)")

    print(f"\n{COR_TITULO}==================================================={COR_RESET}")


# ==========================================
# EXECUÇÃO PRINCIPAL
# ==========================================
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
            filter=args.filter,
            stop_filter = parar_captura,
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