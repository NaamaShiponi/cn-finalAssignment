
from clientTCP import TCPClient
from clientRUDP import RUDPClient
from clientDHCPAndDNS import DHCPAndDNSClient
import sys



def tcpClient(ip_server, port_server):
    tcp_client = TCPClient('localhost',30760)
    tcp_client.start()

def rudoClient(ip_server, port_server):
    rudp_client = RUDPClient(ip_server, port_server)
    rudp_client.start()
    
def main():
    argument="wlp4s0"
    if len(sys.argv) > 1:
        argument = sys.argv[1]
        print(argument)
    
    #Start connection wish dhcp and dns
    DHCP_DNS_client = DHCPAndDNSClient(argument)
    ip_server,domain_name=DHCP_DNS_client.start()
    
    
    if "TCP" in (str)(domain_name):
        port_server=30760
        #Create the TCP server address
        tcpClient(ip_server, port_server)
    if "RUDP" in (str)(domain_name):
        port_server=31760
        #Create the RUDP server address
        rudoClient(ip_server, port_server)

    
    
    
   

if __name__ == "__main__":
    main()