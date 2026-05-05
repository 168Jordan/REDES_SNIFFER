"""
Packet Sniffer — RC TP2
Universidade do Minho, Redes de Computadores 2025/2026

Execução:
    sudo python3 sniffer_gui.py

Requisitos:
    pip install scapy
"""

from scapy.all import sniff, Ether, ARP, IP, ICMP, TCP, UDP, IPv6
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from collections import Counter
from datetime import datetime
import threading
import csv
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox


# ===========================================================================
# Utilitário — detecção de interfaces de rede disponíveis
# ===========================================================================

def obter_interfaces():
    """Devolve lista de interfaces de rede do sistema."""
    ifaces = []
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                nome = parts[1].strip().split("@")[0].strip()
                if nome:
                    ifaces.append(nome)
    except Exception:
        pass

    if not ifaces:
        # fallback: tenta /proc/net/dev
        try:
            with open("/proc/net/dev") as f:
                for linha in f.readlines()[2:]:
                    nome = linha.split(":")[0].strip()
                    if nome:
                        ifaces.append(nome)
        except Exception:
            pass

    if not ifaces:
        ifaces = ["lo", "eth0", "wlan0", "wlo1"]

    # garante que wlo1 aparece se existir no sistema
    preferidas = ["wlo1", "wlan0", "eth0"]
    ordenadas  = []
    for p in preferidas:
        if p in ifaces:
            ordenadas.append(p)
    for i in ifaces:
        if i not in ordenadas:
            ordenadas.append(i)

    return ordenadas


# ===========================================================================
# Estado global da captura
# ===========================================================================

estatisticas  = Counter()
total_pacotes = 0
hora_inicio   = None

stop_event    = threading.Event()
captura_ativa = False


# ===========================================================================
# Lógica de filtragem (original preservada)
# ===========================================================================

def aplicar_filtros(pacote, args):
    if args["proto"]:
        proto = args["proto"].upper()
        if proto == "ARP"  and not pacote.haslayer(ARP):  return False
        if proto == "ICMP" and not pacote.haslayer(ICMP): return False
        if proto == "TCP"  and not pacote.haslayer(TCP):  return False
        if proto == "UDP"  and not pacote.haslayer(UDP):  return False
        if proto == "DNS"  and not (pacote.haslayer(UDP) and
            (pacote[UDP].sport == 53  or pacote[UDP].dport == 53)):   return False
        if proto == "NTP"  and not (pacote.haslayer(UDP) and
            (pacote[UDP].sport == 123 or pacote[UDP].dport == 123)):  return False
        if proto == "DHCP" and not (pacote.haslayer(UDP) and
            (pacote[UDP].sport in (67,68) or pacote[UDP].dport in (67,68))): return False
        if proto == "MDNS" and not (pacote.haslayer(UDP) and
            (pacote[UDP].sport == 5353 or pacote[UDP].dport == 5353)): return False
    if args["ip"]:
        if not pacote.haslayer(IP): return False
        if pacote[IP].src != args["ip"] and pacote[IP].dst != args["ip"]: return False
    if args["mac"]:
        if not pacote.haslayer(Ether): return False
        if pacote[Ether].src.lower() != args["mac"].lower() and \
           pacote[Ether].dst.lower() != args["mac"].lower(): return False
    return True


# ===========================================================================
# Processamento de pacote (original preservado + thread-safe)
# ===========================================================================

def processar_pacote(pacote, args, gui_callback):
    global total_pacotes, estatisticas

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tamanho   = len(pacote)
    protocolo = "?"
    ip_src = ip_dst = "-"
    resumo = "Protocolo desconhecido"

    mac_src = pacote[Ether].src if pacote.haslayer(Ether) else "?"
    mac_dst = pacote[Ether].dst if pacote.haslayer(Ether) else "?"

    # ARP
    if pacote.haslayer(ARP):
        arp = pacote[ARP]
        protocolo = "ARP"
        ip_src = arp.psrc
        ip_dst = arp.pdst
        if arp.op == 1:
            resumo = f"ARP Request: Quem tem {arp.pdst}? Diz a {arp.psrc}"
        else:
            resumo = f"ARP Reply: {arp.psrc} esta em {arp.hwsrc}"

    # IPv4
    elif pacote.haslayer(IP):
        ip_src = pacote[IP].src
        ip_dst = pacote[IP].dst

        if pacote.haslayer(ICMP):
            icmp      = pacote[ICMP]
            protocolo = "ICMP"
            tipo = ("Echo Request" if icmp.type == 8 else
                    "Echo Reply"   if icmp.type == 0 else f"Tipo {icmp.type}")
            resumo = f"ICMP {tipo}: {ip_src} -> {ip_dst}"

        elif pacote.haslayer(TCP):
            tcp   = pacote[TCP]
            flags = tcp.sprintf("%flags%")
            if   "S" in flags and "A" not in flags: desc = "SYN - inicio handshake"
            elif "S" in flags and "A"     in flags: desc = "SYN-ACK - resposta handshake"
            elif "F" in flags:                       desc = "FIN - inicio fecho"
            elif "R" in flags:                       desc = "RST - reset"
            else:                                    desc = flags
            sport, dport = tcp.sport, tcp.dport
            if   sport == 80  or dport == 80:
                protocolo = "HTTP";  resumo = f"HTTP :{sport} -> :{dport}"
            elif sport == 443 or dport == 443:
                protocolo = "HTTPS"; resumo = f"HTTPS :{sport} -> :{dport}"
            elif sport == 21  or dport == 21:
                protocolo = "FTP";   resumo = f"FTP :{sport} -> :{dport}"
            elif sport == 22  or dport == 22:
                protocolo = "SSH";   resumo = f"SSH :{sport} -> :{dport}"
            else:
                protocolo = "TCP"
                resumo    = f"TCP {desc} :{sport} -> :{dport}"

        elif pacote.haslayer(UDP):
            udp = pacote[UDP]
            sport, dport = udp.sport, udp.dport
            if sport == 123 or dport == 123:
                protocolo = "NTP"; resumo = "NTP sync"
            elif sport == 53 or dport == 53:
                protocolo = "DNS"
                if pacote.haslayer(DNS) and pacote[DNS].qd:
                    try:
                        dom  = pacote[DNS].qd.qname.decode(errors="replace").rstrip(".")
                        tipo = "Query" if pacote[DNS].qr == 0 else "Reply"
                        resumo = f"DNS {tipo}: {dom}"
                    except Exception:
                        resumo = "DNS"
                else:
                    resumo = "DNS"
            elif sport == 5353 or dport == 5353:
                protocolo = "mDNS"
                if pacote.haslayer(DNS) and pacote[DNS].qd:
                    try:
                        dom    = pacote[DNS].qd.qname.decode(errors="replace").rstrip(".")
                        resumo = f"mDNS Query: {dom}"
                    except Exception:
                        resumo = "mDNS"
                else:
                    resumo = "mDNS"
            elif sport in (67, 68) or dport in (67, 68):
                protocolo = "DHCP"
                tipos = {1:"Discover", 2:"Offer", 3:"Request", 5:"ACK", 6:"NAK"}
                tipo_dhcp = "?"
                if pacote.haslayer(DHCP):
                    for opt in pacote[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "message-type":
                            tipo_dhcp = tipos.get(opt[1], str(opt[1]))
                            break
                resumo = f"DHCP {tipo_dhcp}"
            else:
                protocolo = "UDP"
                resumo    = f"UDP :{sport} -> :{dport}"
        else:
            protocolo = "IPv4"
            resumo    = f"IPv4 (protocolo desconhecido) ({pacote[IP].proto})"

    elif pacote.haslayer(IPv6):
        ip6 = pacote[IPv6]
        ip_src, ip_dst = ip6.src, ip6.dst
        protocolo = "IPv6"
        resumo    = f"IPv6: {ip_src} -> {ip_dst}"

    total_pacotes += 1
    estatisticas[protocolo] += 1

    linha = (f"[{timestamp}] [{args['interface']}] {tamanho:>5}B"
             f" | {protocolo:<8}"
             f" | {mac_src} -> {mac_dst}"
             f" | {ip_src} -> {ip_dst}"
             f" | {resumo}")

    # envia para a GUI de forma thread-safe através de um dict estruturado
    info = {
        "linha":    linha,
        "protocolo": protocolo,
        "total":    total_pacotes,
        "ts":       timestamp,
        "iface":    args["interface"],
        "size":     tamanho,
        "mac_src":  mac_src,
        "mac_dst":  mac_dst,
        "ip_src":   ip_src,
        "ip_dst":   ip_dst,
        "resumo":   resumo,
    }
    gui_callback(info)


# ===========================================================================
# Interface Gráfica
# ===========================================================================

class SnifferGUI:

    PROTO_CORES = {
        "TCP":   "#4fc3f7",
        "UDP":   "#81c784",
        "DNS":   "#ffb74d",
        "HTTP":  "#ce93d8",
        "HTTPS": "#b39ddb",
        "SSH":   "#f48fb1",
        "ARP":   "#fff176",
        "ICMP":  "#ef9a9a",
        "NTP":   "#80cbc4",
        "DHCP":  "#ffcc80",
        "mDNS":  "#b0bec5",
        "FTP":   "#a5d6a7",
        "IPv6":  "#90caf9",
        "IPv4":  "#eeeeee",
        "?":     "#616161",
    }

    def __init__(self, root):
        self.root = root
        root.title("Packet Sniffer — RC TP2  |  UMinho 2025/2026")
        root.configure(bg="#1a1a2e")
        root.minsize(960, 680)

        self._pacotes_cache  = []
        self._n              = 0
        self._barras_widgets = {}
        self._sniffer_thread = None
        self._ordem_iids     = []   # mantém a ordem original dos iids da tabela

        self._interfaces = obter_interfaces()

        self._build_ui()

    # -----------------------------------------------------------------------
    # Construção da UI
    # -----------------------------------------------------------------------

    def _build_ui(self):

        # ── Barra de controlo superior ──────────────────────────────────────
        ctrl = tk.Frame(self.root, bg="#16213e", pady=8, padx=10)
        ctrl.pack(fill="x")

        # Interface — combobox com interfaces detectadas
        tk.Label(ctrl, text="Interface:", bg="#16213e", fg="#e0e0e0",
                 font=("Consolas", 10)).pack(side="left")
        self.var_iface = tk.StringVar(value=self._interfaces[0] if self._interfaces else "wlo1")
        self.cb_iface = ttk.Combobox(
            ctrl, textvariable=self.var_iface,
            values=self._interfaces, width=9,
            font=("Consolas", 10), state="readonly")
        self.cb_iface.pack(side="left", padx=(2, 12))

        # botão para refrescar lista de interfaces
        tk.Button(ctrl, text="⟳", command=self._refresh_ifaces,
            bg="#0f3460", fg="#90caf9", relief="flat",
            font=("Consolas", 10), padx=4, cursor="hand2"
        ).pack(side="left", padx=(0, 12))

        tk.Label(ctrl, text="Count:", bg="#16213e", fg="#e0e0e0",
                 font=("Consolas", 10)).pack(side="left")
        self.var_count = tk.StringVar(value="0")
        tk.Entry(ctrl, textvariable=self.var_count, width=6,
                 bg="#0f3460", fg="white", insertbackground="white",
                 relief="flat", font=("Consolas", 10)).pack(side="left", padx=(2, 12))

        tk.Label(ctrl, text="BPF:", bg="#16213e", fg="#e0e0e0",
                 font=("Consolas", 10)).pack(side="left")
        self.var_bpf = tk.StringVar()
        tk.Entry(ctrl, textvariable=self.var_bpf, width=14,
                 bg="#0f3460", fg="white", insertbackground="white",
                 relief="flat", font=("Consolas", 10)).pack(side="left", padx=(2, 12))

        # ── Botões de acção ──────────────────────────────────────────────────
        self.btn_start = tk.Button(ctrl, text="▶  START",
            command=self._start,
            bg="#00b894", fg="white", activebackground="#00cec9",
            relief="flat", font=("Consolas", 10, "bold"),
            padx=12, pady=4, cursor="hand2")
        self.btn_start.pack(side="left", padx=4)

        self.btn_stop = tk.Button(ctrl, text="■  STOP",
            command=self._stop,
            bg="#d63031", fg="white", activebackground="#e17055",
            relief="flat", font=("Consolas", 10, "bold"),
            padx=12, pady=4, cursor="hand2", state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self.btn_restart = tk.Button(ctrl, text="↺  RESTART",
            command=self._restart,
            bg="#6c5ce7", fg="white", activebackground="#a29bfe",
            relief="flat", font=("Consolas", 10, "bold"),
            padx=12, pady=4, cursor="hand2")
        self.btn_restart.pack(side="left", padx=4)

        tk.Button(ctrl, text="🗑  Limpar",
            command=self._limpar,
            bg="#636e72", fg="white", activebackground="#b2bec3",
            relief="flat", font=("Consolas", 10),
            padx=10, pady=4, cursor="hand2"
        ).pack(side="left", padx=4)

        tk.Button(ctrl, text="💾  Guardar CSV",
            command=self._guardar_csv,
            bg="#0984e3", fg="white", activebackground="#74b9ff",
            relief="flat", font=("Consolas", 10),
            padx=10, pady=4, cursor="hand2"
        ).pack(side="left", padx=4)

        self.lbl_status = tk.Label(ctrl, text="● Parado",
            bg="#16213e", fg="#e17055",
            font=("Consolas", 10, "bold"))
        self.lbl_status.pack(side="right", padx=8)

        # ── Barra de filtro/pesquisa (linha 2) ──────────────────────────────
        flt = tk.Frame(self.root, bg="#0d0d1a", pady=5, padx=10)
        flt.pack(fill="x")

        # variáveis internas mantidas para compatibilidade com _build_args
        self.var_proto = tk.StringVar()
        self.var_ip    = tk.StringVar()
        self.var_mac   = tk.StringVar()

        # label + campo de pesquisa livre
        tk.Label(flt, text="Filtro:", bg="#0d0d1a", fg="#aaa",
                 font=("Consolas", 9)).pack(side="left")
        self.var_pesquisa = tk.StringVar()
        self.var_pesquisa.trace_add("write", lambda *_: self._aplicar_pesquisa())
        tk.Entry(flt, textvariable=self.var_pesquisa, width=34,
                 bg="#1a1a2e", fg="white", insertbackground="white",
                 relief="flat", font=("Consolas", 9)
                 ).pack(side="left", padx=(4, 4))
        tk.Label(flt, text="(ex: TCP  |  192.168.1.1  |  DNS  |  :443)",
                 bg="#0d0d1a", fg="#444", font=("Consolas", 8)
                 ).pack(side="left", padx=(0, 16))

        # botão para limpar o filtro
        tk.Button(flt, text="✕", command=lambda: self.var_pesquisa.set(""),
            bg="#0d0d1a", fg="#666", activeforeground="white",
            relief="flat", font=("Consolas", 9), cursor="hand2", padx=2
        ).pack(side="left", padx=(0, 20))

        # contador de linhas visíveis
        self.lbl_visiveis = tk.Label(flt, text="",
            bg="#0d0d1a", fg="#555", font=("Consolas", 8))
        self.lbl_visiveis.pack(side="left", padx=(0, 20))

        # indicador de hora de início (mantido do lado direito)
        tk.Label(flt, text="Inicio:", bg="#0d0d1a", fg="#555",
                 font=("Consolas", 9)).pack(side="left", padx=(0, 2))
        self.lbl_inicio = tk.Label(flt, text="—",
            bg="#0d0d1a", fg="#81c784", font=("Consolas", 9))
        self.lbl_inicio.pack(side="left")

        # ── Painel central dividido verticalmente ───────────────────────────
        centro = tk.PanedWindow(self.root, orient="vertical",
                                bg="#1a1a2e", sashwidth=6, sashpad=2)
        centro.pack(fill="both", expand=True, padx=8, pady=(4, 0))

        # -- Tabela de pacotes
        frame_tabela = tk.Frame(centro, bg="#1a1a2e")
        centro.add(frame_tabela, minsize=220)

        self._estilizar_treeview()

        cols   = ("#", "Timestamp", "Proto", "IP Src", "IP Dst",
                  "MAC Src", "MAC Dst", "Resumo", "Bytes")
        widths = [40, 155, 72, 125, 125, 135, 135, 0, 58]

        vsb = ttk.Scrollbar(frame_tabela, orient="vertical")
        hsb = ttk.Scrollbar(frame_tabela, orient="horizontal")

        self.tree = ttk.Treeview(frame_tabela, columns=cols,
                                 show="headings", selectmode="browse",
                                 yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set)
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w",
                             stretch=(c == "Resumo"), minwidth=30)

        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # -- Painel inferior: log raw  +  estatísticas
        inferior = tk.PanedWindow(centro, orient="horizontal",
                                  bg="#1a1a2e", sashwidth=6)
        centro.add(inferior, minsize=150)

        # Log raw
        frame_log = tk.Frame(inferior, bg="#0d0d1a")
        inferior.add(frame_log, minsize=320)
        tk.Label(frame_log, text=" LOG RAW", bg="#0d0d1a", fg="#555",
                 font=("Consolas", 8)).pack(anchor="w", padx=4, pady=(2, 0))
        self.txt_log = scrolledtext.ScrolledText(
            frame_log, bg="#0d0d1a", fg="#00ff88",
            font=("Consolas", 9), state="disabled",
            relief="flat", insertbackground="white")
        self.txt_log.pack(fill="both", expand=True)

        # Estatísticas
        frame_stats = tk.Frame(inferior, bg="#111122", padx=8, pady=6)
        inferior.add(frame_stats, minsize=220)
        tk.Label(frame_stats, text=" ESTATISTICAS", bg="#111122", fg="#555",
                 font=("Consolas", 8)).pack(anchor="w")
        self.lbl_total = tk.Label(frame_stats, text="Total: 0",
            bg="#111122", fg="#e0e0e0", font=("Consolas", 11, "bold"))
        self.lbl_total.pack(anchor="w", pady=(4, 8))
        self.frame_barras = tk.Frame(frame_stats, bg="#111122")
        self.frame_barras.pack(fill="both", expand=True)

        # ── Rodapé ──────────────────────────────────────────────────────────
        rodape = tk.Frame(self.root, bg="#0d0d1a", pady=3, padx=10)
        rodape.pack(fill="x")
        self.lbl_rodape = tk.Label(rodape, text="Pronto.",
            bg="#0d0d1a", fg="#555", font=("Consolas", 8))
        self.lbl_rodape.pack(side="left")

    def _estilizar_treeview(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background="#12122a", foreground="#e0e0e0",
            rowheight=22, fieldbackground="#12122a",
            font=("Consolas", 9))
        style.configure("Treeview.Heading",
            background="#0f3460", foreground="#90caf9",
            font=("Consolas", 9, "bold"), relief="flat")
        style.map("Treeview",
            background=[("selected", "#0f3460")])
        style.configure("Vertical.TScrollbar",
            background="#1a1a2e", troughcolor="#0d0d1a")
        style.configure("Horizontal.TScrollbar",
            background="#1a1a2e", troughcolor="#0d0d1a")
        style.configure("TCombobox",
            fieldbackground="#0f3460", background="#0f3460",
            foreground="white", selectbackground="#0f3460")

    # -----------------------------------------------------------------------
    # Acções dos botões
    # -----------------------------------------------------------------------

    def _refresh_ifaces(self):
        """Actualiza a lista de interfaces detectadas."""
        self._interfaces = obter_interfaces()
        self.cb_iface["values"] = self._interfaces
        self._log("Interfaces actualizadas: " + ", ".join(self._interfaces) + "\n")

    def _build_args(self):
        try:
            count = int(self.var_count.get() or 0)
        except ValueError:
            count = 0
        return {
            "interface": self.var_iface.get().strip() or "wlo1",
            "count":     count,
            "filter":    self.var_bpf.get().strip(),
            "proto":     self.var_proto.get().strip(),
            "ip":        self.var_ip.get().strip(),
            "mac":       self.var_mac.get().strip(),
        }

    def _start(self):
        global captura_ativa, stop_event, hora_inicio
        global total_pacotes, estatisticas

        total_pacotes = 0
        estatisticas  = Counter()
        hora_inicio   = datetime.now()
        stop_event    = threading.Event()
        captura_ativa = True

        args = self._build_args()

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text="● A capturar...", fg="#00b894")
        self.lbl_inicio.config(
            text=hora_inicio.strftime("%d/%m/%Y  %H:%M:%S"))
        self._log(f"[{hora_inicio.strftime('%H:%M:%S')}] "
                  f"Iniciando captura em '{args['interface']}'...\n")

        self._sniffer_thread = threading.Thread(
            target=self._run_sniffer, args=(args,), daemon=True)
        self._sniffer_thread.start()

    def _run_sniffer(self, args):
        def callback(pkt):
            if stop_event.is_set():
                return
            if aplicar_filtros(pkt, args):
                processar_pacote(pkt, args, self._gui_update)

        try:
            sniff(
                iface=args["interface"],
                prn=callback,
                count=args["count"],
                filter=args["filter"],
                store=False,
                stop_filter=lambda _: stop_event.is_set()
            )
        except Exception as exc:
            err_msg = str(exc)
            self.root.after(0, lambda msg=err_msg: self._log(f"ERRO: {msg}\n"))
        finally:
            self.root.after(0, self._captura_terminada)

    def _stop(self):
        stop_event.set()
        self.lbl_status.config(text="● A parar...", fg="#fdcb6e")

    def _restart(self):
        """Para a captura actual, limpa e inicia de novo com as mesmas definições."""
        if captura_ativa:
            stop_event.set()
            # espera brevemente que a thread termine antes de reiniciar
            self.root.after(600, self._restart_fase2)
        else:
            self._restart_fase2()

    def _restart_fase2(self):
        self._limpar_dados()
        self._start()

    def _captura_terminada(self):
        global captura_ativa
        captura_ativa = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="● Parado", fg="#e17055")
        self._mostrar_resumo()

    def _mostrar_resumo(self):
        if hora_inicio is None:
            return
        duracao = datetime.now() - hora_inicio
        msg = (f"\n{'='*52}\n RESUMO FINAL\n{'='*52}\n"
               f" Duracao   : {str(duracao).split('.')[0]}\n"
               f" Total pkt : {total_pacotes}\n{'-'*52}\n")
        for proto, qtd in estatisticas.most_common():
            pct = qtd / total_pacotes * 100 if total_pacotes else 0
            msg += f"  {proto:<8}: {qtd:>5} pkts  ({pct:>5.1f}%)\n"
        msg += "=" * 52 + "\n"
        self._log(msg)

    def _limpar_dados(self):
        """Limpa apenas os dados (tabela, log, cache) sem tocar nos filtros."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        # apagar também os detached (não aparecem em get_children)
        for iid in self._ordem_iids:
            try:
                self.tree.delete(iid)
            except Exception:
                pass
        self._ordem_iids.clear()
        self.txt_log.config(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.config(state="disabled")
        self._pacotes_cache.clear()
        self._n = 0
        self.lbl_total.config(text="Total: 0")
        self.lbl_visiveis.config(text="")
        for w in self.frame_barras.winfo_children():
            w.destroy()
        self._barras_widgets.clear()
        self.lbl_inicio.config(text="—")

    def _limpar(self):
        """Limpa tudo e para a captura se estiver activa."""
        if captura_ativa:
            stop_event.set()
        self._limpar_dados()

    def _guardar_csv(self):
        """Guarda a captura num CSV com timestamp no nome do ficheiro."""
        if not self._pacotes_cache:
            messagebox.showinfo("Guardar CSV", "Nenhum pacote para guardar.")
            return

        # nome padrão com data e hora exactas da captura
        ts_nome = (hora_inicio.strftime("%Y-%m-%d_%H-%M-%S")
                   if hora_inicio else datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
        iface   = self.var_iface.get().strip().replace("/", "-")
        default = f"captura_{iface}_{ts_nome}.csv"

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
            initialfile=default,
            title="Guardar captura como...")

        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["n", "timestamp", "interface", "tamanho",
                            "protocolo", "mac_src", "mac_dst",
                            "ip_src", "ip_dst", "resumo"])
                for p in self._pacotes_cache:
                    w.writerow([p["n"], p["ts"], p["iface"], p["size"],
                                p["proto"], p["mac_src"], p["mac_dst"],
                                p["ip_src"], p["ip_dst"], p["resumo"]])
            self._log(f"Guardado: {path}  ({len(self._pacotes_cache)} pacotes)\n")
        except Exception as exc:
            messagebox.showerror("Erro ao guardar", str(exc))

    def _on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals:
            self.lbl_rodape.config(
                text=f"  [{vals[2]}]  {vals[7]}"
            )

    def _aplicar_pesquisa(self):
        """Filtra a tabela em tempo real.
        Pesquisa em todos os campos: protocolo, IP, MAC, resumo, timestamp.
        """
        termo = self.var_pesquisa.get().strip().lower()
        visiveis = 0

        for iid in self._ordem_iids:
            try:
                vals  = self.tree.item(iid, "values")
                texto = " ".join(str(v) for v in vals).lower()
                if termo == "" or termo in texto:
                    # mostrar — reattach na posição correcta (end mantém ordem)
                    self.tree.reattach(iid, "", "end")
                    visiveis += 1
                else:
                    # esconder
                    self.tree.detach(iid)
            except Exception:
                pass

        total = len(self._pacotes_cache)
        if termo:
            self.lbl_visiveis.config(
                text=f"{visiveis} / {total} pacotes",
                fg="#ffb74d" if visiveis < total else "#81c784")
        else:
            self.lbl_visiveis.config(text="", fg="#555")
            # quando limpa o filtro, scroll para o fim
            self.tree.yview_moveto(1)

    # -----------------------------------------------------------------------
    # Actualização thread-safe da GUI
    # -----------------------------------------------------------------------

    def _gui_update(self, info):
        """Chamado da thread de sniff; agenda inserção na thread da GUI."""
        self.root.after(0, lambda i=info: self._inserir(i))

    def _inserir(self, info):
        proto = info["protocolo"]
        cor   = self.PROTO_CORES.get(proto, "#eeeeee")

        self._n += 1
        info["n"] = self._n

        tag = f"cor_{proto}"
        self.tree.tag_configure(tag, foreground=cor)
        iid = self.tree.insert("", "end", tags=(tag,), values=(
            self._n,
            info["ts"],
            proto,
            info["ip_src"],
            info["ip_dst"],
            info["mac_src"],
            info["mac_dst"],
            info["resumo"],
            info["size"],
        ))

        # guardar iid para poder fazer detach/reattach na pesquisa
        self._ordem_iids.append(iid)

        # se há filtro activo, esconder a linha se não corresponder
        termo = self.var_pesquisa.get().strip().lower()
        if termo:
            vals  = self.tree.item(iid, "values")
            texto = " ".join(str(v) for v in vals).lower()
            if termo not in texto:
                self.tree.detach(iid)
            else:
                self.tree.yview_moveto(1)
            # actualizar contador visíveis
            visiveis = len(self.tree.get_children(""))
            total    = len(self._pacotes_cache) + 1  # +1 porque cache ainda não tem este
            self.lbl_visiveis.config(
                text=f"{visiveis} / {total} pacotes",
                fg="#ffb74d" if visiveis < total else "#81c784")
        else:
            self.tree.yview_moveto(1)

        # cache para CSV
        self._pacotes_cache.append(info)

        # log raw
        self._log(info["linha"] + "\n")

        # contador e barras
        self.lbl_total.config(text=f"Total: {info['total']}")
        self._atualizar_barras()

    def _log(self, texto):
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", texto)
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")

    def _atualizar_barras(self):
        if total_pacotes == 0:
            return
        for proto, qtd in estatisticas.most_common(12):
            pct = qtd / total_pacotes
            cor = self.PROTO_CORES.get(proto, "#aaa")

            if proto not in self._barras_widgets:
                row = tk.Frame(self.frame_barras, bg="#111122")
                row.pack(fill="x", pady=1)
                lbl_nome = tk.Label(row, text=f"{proto:<6}",
                    bg="#111122", fg=cor,
                    font=("Consolas", 8), width=7, anchor="w")
                lbl_nome.pack(side="left")
                canvas = tk.Canvas(row, height=12, bg="#1e1e3a",
                                   highlightthickness=0)
                canvas.pack(side="left", fill="x", expand=True)
                lbl_pct = tk.Label(row, text="",
                    bg="#111122", fg=cor,
                    font=("Consolas", 8), width=9, anchor="e")
                lbl_pct.pack(side="left")
                self._barras_widgets[proto] = (canvas, lbl_pct, cor)

            canvas, lbl_pct, cor = self._barras_widgets[proto]
            canvas.update_idletasks()
            w = canvas.winfo_width()
            canvas.delete("all")
            canvas.create_rectangle(0, 0, int(w * pct), 12,
                                    fill=cor, outline="")
            lbl_pct.config(text=f"{qtd:>4}  {pct*100:>4.0f}%")


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app  = SnifferGUI(root)
    root.mainloop()