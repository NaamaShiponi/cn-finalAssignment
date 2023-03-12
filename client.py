
from clientTCP import TCPClient
from clientRUDP import RUDPClient
from clientDHCPAndDNS import DHCPAndDNSClient



def tcpClient(ip_server, port_server):
    tcp_client = TCPClient(ip_server, port_server)
    tcp_client.start()

def rudoClient(ip_server, port_server):
    rudp_client = RUDPClient(ip_server, port_server)
    rudp_client.start()
    
def main():
    
    #Start connection wish dhcp and dns
    DHCP_DNS_client = DHCPAndDNSClient()
    ip_server,domain_name=DHCP_DNS_client.start()
    
    
    if "TCP" in (str)(domain_name):
        port_server=9999
        #Create the TCP server address
        tcpClient(ip_server, port_server)
    if "RUDP" in (str)(domain_name):
        port_server=5001
        #Create the RUDP server address
        rudoClient(ip_server, port_server)

    
    
    
   

if __name__ == "__main__":
    main()