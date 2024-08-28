from scapy.all import sniff, IP, TCP, Ether
import socket
import whois

def resolve_domain(ip_address):
    try:
        domain = socket.gethostbyaddr(ip_address)
        return domain[0]
    except socket.herror:
        return None

def whois_lookup(ip_address):
    try:
        w = whois.whois(ip_address)
        return w.domain_name if w.domain_name else 'Desconhecido'
    except Exception as e:
        return 'Desconhecido'

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)

        if tcp_layer.dport == 443 or tcp_layer.sport == 443:
            src_domain = resolve_domain(ip_layer.src)
            dst_domain = resolve_domain(ip_layer.dst)
            
            if src_domain is None:
                src_domain = whois_lookup(ip_layer.src)
            if dst_domain is None:
                dst_domain = whois_lookup(ip_layer.dst)
            
            print(f"Pacote HTTPS Capturado:")
            print(f"  - Endereço IP de Origem: {ip_layer.src} (Domínio: {src_domain})")
            print(f"  - Endereço IP de Destino: {ip_layer.dst} (Domínio: {dst_domain})")
            print(f"  - Porta de Origem: {tcp_layer.sport}")
            print(f"  - Porta de Destino: {tcp_layer.dport}")
            print(f"  - Número de Sequência: {tcp_layer.seq}")
            print(f"  - Número de Confirmação: {tcp_layer.ack}")
            print(f"  - Flags TCP: {tcp_layer.flags}")
            print(f"  - TTL: {ip_layer.ttl}")
            print(f"  - Protocolo: {ip_layer.proto}")
            print(f"  - Tamanho Total do Pacote: {ip_layer.len}")
            print(f"  - Timestamp do Pacote: {packet.time}")
            print("-" * 50)

def main(interface):
    print(f"Iniciando captura de pacotes na interface {interface}...")
    sniff(iface=interface, prn=process_packet, filter="tcp", store=0)

if __name__ == "__main__":
    interface = input("Digite a interface de rede para captura (ex: eth0, wlan0): ")
    main(interface)
