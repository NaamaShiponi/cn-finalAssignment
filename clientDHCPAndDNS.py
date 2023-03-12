from scapy.all import *
import random


class DHCPAndDNSClient:
    def __init__(self):
        self.IP_ADDRESS = "0.0.0.0"
        self.PORT = 52

    def create_dhcp_discover(self,mac_addr,xid):
        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_addr)/\
                    IP(src="0.0.0.0", dst="255.255.255.255")/\
                    UDP(sport=68, dport=67)/\
                    BOOTP(chaddr=mac_addr, xid=xid)/\
                    DHCP(options=[("message-type", "discover"),
                                "end"])
        return dhcp_discover

    def create_dhcp_request(self,mac_addr,xid,ip_client):
        dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_addr)/\
                    IP(src="0.0.0.0", dst="255.255.255.255")/\
                    UDP(sport=68, dport=67)/\
                    BOOTP(chaddr=mac_addr, xid=xid)/\
                    DHCP(options=[("message-type", "request"),
                                ("server_id", "192.168.1.100"),
                                ("requested_addr", ip_client),
                                "end"])
        return dhcp_request
    def create_dns_request(self,domain_name,DNS_SERVER_IP,DNS_SERVER_PORT):
        # Construct a DNS query packet
        dns_query = IP(dst=DNS_SERVER_IP)/\
                    UDP(dport=DNS_SERVER_PORT)/\
                    DNS(rd=1,qd=DNSQR(qname=domain_name))

        # Send the query to the DNS server and wait for a response
        return sr1(dns_query)

        


    def start(self):
        ip_client="0.0.0.0"
        # Construct the DHCP Discover packet
        mac_addr = "08:00:27:56:58:68" # MAC address of the client
        xid = random.randint(1, 100000) # Transaction ID
        DNS_SERVER_PORT = 52
        recvSize=1024
            #Create dhcp discover packet
        dhcp_discover= self.create_dhcp_discover(mac_addr,xid)

        # Send the DHCP Discover packet and wait for a response
        sendp(dhcp_discover)
        ip_client= None
        ip_dns=None
        
        while not ip_dns:
            dhcp_discover = sniff(filter="udp and (port 67 or 68)",timeout=3, iface="wlp4s0")

            if len(dhcp_discover) > 0:
                print("Received DHCP response:")
                # dhcp_response[0].show()
                ip_client = dhcp_discover[0][BOOTP].yiaddr
                for name in dhcp_discover[0][DHCP].options:
                    if name[0]=="name_server":
                        ip_dns=name[1]                          
                # ip_dns=dhcp_discover[0][DHCP].options[3][1]
                # name_server

            else:
                print("No response received")
            
        print("offer IP fron dhcp ",ip_client)

        print("dns ip ",ip_dns)
        # Construct the DHCP request packet
        dhcp_request= self.create_dhcp_request(mac_addr,xid,ip_client)

        # Send the DHCP request packet and wait for a response
        sendp(dhcp_request)

        # Sniffer to port 67 or 68 requests
        dhcp_response = sniff(filter="udp and (port 67 or 68)", timeout=1, iface="wlp4s0")

        #get domain 
        domain_name = input("Enter the domain to lookup (e.g. www.server-RUDP.com/www.server-TCP.com): ")
        
        response=self.create_dns_request(domain_name,ip_dns,DNS_SERVER_PORT)
        
        # Extract the IP address from the response and print it
        ip_address = response[DNS].an.rdata
        print(f'{domain_name} has IP address: {ip_address}')
        
        return ip_address ,domain_name
        
    
