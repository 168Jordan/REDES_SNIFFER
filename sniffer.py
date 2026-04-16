from scapy.all import sniff

def processar_pacote(pacote):
    print(f"Apanhei um pacote com {len(pacote)} bytes de tamanho!")
    
    # O próximo passo será fazer o cast para as estruturas dos protocolos
    # ex: eth = pacote[Ether]

sniff(iface="eth0", prn=processar_pacote, count=10)