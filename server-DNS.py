
    
    
from scapy.all import *
import socket

# dictionary of addresses and IP
DNS_IP_TABLE = {
    'www.server-RUDP.com': 'localhost',
    'www.server-TCP.com': 'localhost',
}

# Function for checking data in a received package and sending an answer
def handle_dns_query(packet):
   

    # Take out the domain form the package
    domain_name = packet[DNS].qd.qname.decode('utf-8')[:-1]
    print(f"message client: DNS msg fo domain_name{domain_name}")

    # Look up the IP address for the domain name
    if domain_name in DNS_IP_TABLE.keys():
        ip_address = DNS_IP_TABLE[domain_name]     
    else:
        try:
            ip_address = socket.gethostbyname(domain_name)
        except socket.gaierror:
            ip_address="Unknown"
            
    # Create a DNS response packet wish IP for the domain
    dns_response = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                   UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                   DNS(id=packet[DNS].id, qr=1, qd=packet[DNS].qd,\
                       an=DNSRR(rrname=domain_name+'.', type='A', ttl=86400, rdata=ip_address))

    # Send the response packet back to the client
    send(dns_response, verbose=0)
    print(f"message server: response DNS wish ip {ip_address}")

def main():
    print("DNS server listening to filter udp port 52")
    # Sniffer to intercept DNS requests and handle them
    sniff(filter='udp port 52 and udp[10] & 0x80 = 0', prn=handle_dns_query, iface='lo')
    
if __name__ == "__main__":
    main()
    
    

