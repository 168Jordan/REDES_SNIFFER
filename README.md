# REDES_SNIFFER
Passo 1 — Argparse (interface + filtros)
O enunciado diz que tens de permitir selecionar a interface e filtrar tráfego. Agora está tudo hardcoded.
O que fazer:

Adicionar argparse para receber -i (interface), -c (count), --proto, --ip, --mac, -f (filtro BPF)
Aplicar os filtros dentro do processar_pacote
FEITO 168

Passo 2 — Mostrar a interface no output
O enunciado pede que o output inclua a interface onde o pacote foi capturado. Agora não mostras isso.
O que fazer:

Adicionar o nome da interface em cada linha impressa


Passo 3 — Modo log (ficheiro)
O enunciado pede modo live (consola) e modo log (ficheiro), podendo estar os dois ativos ao mesmo tempo.
O que fazer:

Adicionar argumento --log captura.csv
Guardar cada pacote em CSV com os mesmos campos do print


Passo 4 — Mais protocolos
O enunciado pede identificação de protocolos das aulas teóricas. Os que tens são básicos.
O que fazer:

HTTP — TCP porta 80 (identificar GET, POST, etc.)
HTTPS — TCP porta 443
FTP — TCP porta 21
DHCP — já tens deteção mas sem detalhes (Discover, Offer, Request, ACK)
DNS — já tens mas sem mostrar o domínio pedido


Passo 5 — Detalhe nos protocolos existentes
O enunciado pede "resumo do conteúdo" mais rico e identificação das trocas características.
O que fazer:

DNS: mostrar o domínio (pacote[DNS].qd.qname)
TCP: identificar handshake (SYN → SYN-ACK → ACK) e fecho (FIN)
DHCP: mostrar tipo (Discover/Offer/Request/ACK)


Passo 6 — Topologia no CORE (Parte A)
O enunciado pede uma topologia no emulador CORE com o sniffer a correr num nó.
O que fazer:

Criar topologia: 2 PCs + 1 router
Correr o sniffer num PC
Fazer ping, netcat, HTTP entre os outros nós
Capturar e guardar em ficheiro


Passo 7 — README completo
O enunciado lista explicitamente o que o README deve ter.
O que fazer:

Dependências
Como selecionar interface
Como ativar filtros
Como correr no CORE e no PC
