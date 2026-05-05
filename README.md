# Packet Sniffer em Python (RC-TP2)

- José Ornelas a111790
- Tiago Carvalhido a110491
- Tiago Pereira a112042

---

Este projeto consiste num Packet Sniffer de rede desenvolvido em Python, utilizando a biblioteca Scapy. A ferramenta permite capturar, filtrar, dissecar e registar pacotes de rede em tempo real, suportando ambientes emulados (CORE) e interfaces de rede físicas.

## 1. Dependências e Instalação
Para executar este sniffer, é necessário ter o Python 3 instalado, bem como a biblioteca de dissecação de pacotes scapy.

Instalação da biblioteca no Linux:
Podes instalar o Scapy globalmente via gestor de pacotes (recomendado para o emulador CORE):

```bash
sudo apt update
sudo apt install python3-scapy
```

Ou através do gestor de pacotes do Python (pip):

```bash
pip3 install scapy
```

## 2. Modo de Execução
Como a placa de rede precisa de ser colocada em modo promíscuo para capturar o tráfego, o script deve ser executado com privilégios de administrador (sudo).

### Opção A: Menu Interativo
Se executares o script sem argumentos, ser-te-á apresentado um menu passo a passo onde podes escolher a interface a partir de uma lista e configurar todos os filtros de forma guiada:

```bash
sudo python3 sniffer.py
```

### Opção B: Linha de Comandos (CLI)
Para automação ou execuções rápidas, podes passar os argumentos diretamente. Para ver o menu de ajuda com todos os comandos disponíveis:

```bash
python3 sniffer.py -h
```

## 3. Filtros e Parâmetros 

### Controlo de Captura e Interface
- -i ou --interface: Define a placa de rede a escutar (ex: eth0, wlan0). Se omitido, assume eth0.

- -c ou --count: Define um limite exato de pacotes a capturar. O valor 0 (padrão) significa captura infinita até à interrupção (Ctrl+C).

- --log: Especifica o nome do ficheiro para onde os dados serão exportados (ex: captura.csv, dados.json, log.txt).

### Filtros de Baixo Nível (Kernel)
- -f ou --filter: Permite aplicar filtros nativos BPF (Berkeley Packet Filter), que operam diretamente no kernel para máxima performance.

    - Exemplo: -f "tcp port 80 or icmp"

### Filtros de Aplicação (Implementados no Código)
- --proto: Isola um protocolo específico. Suporta: ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, DHCP, NTP, HTTP, HTTPS, FTP, mDNS.

- --ip: Filtra pacotes que tenham um determinado endereço IP como origem ou destino.

- --mac: Filtra pacotes pela sua origem ou destino físico (Endereço MAC).

## 4. Como correr no Emulador CORE
No ambiente esterilizado do emulador CORE, as interfaces assumem nomes genéricos. Como os nós do CORE já funcionam como root, não é necessário usar sudo.

1. Abre o terminal do nó desejado (ex: n1).

2. Confirma o nome da interface com o comando ip addr.

3. Executa o sniffer:

```bash
# Iniciar o menu interativo
python3 sniffer.py

# Ou iniciar diretamente via CLI filtrando por ICMP e exportando para JSON
python3 sniffer.py -i eth0 --proto ICMP --log log_core.json
```

4. Abre o terminal de outro nó (ex: n2) e gera tráfego para testar a captura (ex: ping 10.0.0.1 ou wget [http://10.0.0.1](http://10.0.0.1)).

### 5. Como correr no PC Real (Interface Física)
Numa máquina física, irás capturar o tráfego real da tua rede local. É estritamente necessário usar sudo.

1. Abre o terminal do teu sistema operativo Linux.

2. Descobre o nome da tua placa de rede Wi-Fi ou Ethernet usando o comando ip a (normalmente chama-se wlan0, wlp2s0, enp3s0, etc.).

3. Executa o sniffer apontando para essa interface:

**Exemplos:**

```bash
# Captura de todo o tráfego na placa Wi-Fi
sudo python3 sniffer.py -i wlp2s0

# Capturar tráfego de navegação Web limitando a 100 pacotes
sudo python3 sniffer.py -i wlp2s0 -f "tcp port 80 or tcp port 443" -c 100

# Descobrir dispositivos a falar em Multicast DNS na rede doméstica
sudo python3 sniffer.py -i wlp2s0 --proto MDNS
```

**Nota:** Pressiona Ctrl+C para parar a captura. O sniffer irá intercetar o sinal, imprimir um resumo estatístico final ordenado no ecrã e gravar o ficheiro de log de forma segura.
