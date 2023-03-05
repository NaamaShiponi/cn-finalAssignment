
    
    
from scapy.all import *
import socket

# Set up the DNS server address and port
DNS_TABLE = {
    'www.server-RUDP.com': '192.168.1.100',
    'www.server-TCP.com': '192.168.1.101',
}

# Define a function to handle DNS queries
def handle_dns_query(packet):
    
    # Extra))ct the DNS query from the packet
    dns_query = packet[DNS]

    # Extract the domain name from the query
    domain_name = dns_query.qd.qname.decode('utf-8')[:-1]
    print("domain_name",domain_name)
    # Look up the IP address for the domain name
    if domain_name in DNS_TABLE.keys():
        ip_address = DNS_TABLE[domain_name]        
    else:
        try:
            ip_address = socket.gethostbyname(domain_name)
        except socket.gaierror:
            ip_address="Unknown"
    # Construct a DNS response packet
    
    dns_response = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                   UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                   DNS(id=dns_query.id, qr=1, qd=dns_query.qd,\
                       an=DNSRR(rrname=domain_name+'.', type='A', ttl=86400, rdata=ip_address))

    # Send the response packet back to the client
    send(dns_response, verbose=0)
    
def main():
    print("DNS server listening to filter udp port 52")
    # Set up a Sniffer to intercept DNS requests and handle them
    sniff(filter='udp port 52 and udp[10] & 0x80 = 0', prn=handle_dns_query, iface='lo')
    
if __name__ == "__main__":
    main()
    
    

