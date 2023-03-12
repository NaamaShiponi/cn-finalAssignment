from scapy.all import *
ip_pool = []

DNS_IP='localhost'
class DHCPServer:
    def __init__(self, interface, subnet):
        self.interface = interface
        self.subnet = subnet

    def start(self):
        # start the DHCP server and listen for incoming requests
        sniff(prn=self.handle_dhcp_request, filter="udp and (port 67 or 68)", iface=self.interface)

    def handle_dhcp_request(self, packet):
        # handle incoming DHCP requests and send DHCP responses
        if DHCP in packet and packet[DHCP].options[0][1] == 1: # DHCP Discover packet
            print("Get Discover msg")  
            client_mac = packet[Ether].src
            requested_ip = get_available_ip()
            if requested_ip is not None:
                dhcp_offer = self.create_dhcp_offer(client_mac, requested_ip,DNS_IP)
                print("offerIP ",dhcp_offer[0][BOOTP].yiaddr)
                sendp(dhcp_offer)
                
        elif DHCP in packet and packet[DHCP].options[0][1] == 3: # DHCP Request packet
            print("Get Request msg")
            client_mac = packet[Ether].src
            requested_ip = packet[BOOTP].yiaddr
            dhcp_ack = self.create_dhcp_ack(client_mac, requested_ip)
            sendp(dhcp_ack)

    def create_dhcp_offer(self, client_mac, requested_ip,DNS_IP):
        # create a DHCP Offer packet to send to the client
        dhcp_offer = Ether(src=get_if_hwaddr(self.interface), dst="ff:ff:ff:ff:ff:ff")/\
                     IP(src=self.subnet, dst="255.255.255.255")/\
                     UDP(sport=67, dport=68)/\
                     BOOTP(op=2, yiaddr=requested_ip, siaddr=self.subnet, chaddr=client_mac)/\
                     DHCP(options=[("message-type", "offer"),
                                    ("subnet_mask", "255.255.255.0"),
                                    ("router", self.subnet),
                                    ("name_server", DNS_IP),
                                    ("lease_time", 86400),
                                    "end"])
        return dhcp_offer

    def create_dhcp_ack(self, client_mac, requested_ip):
        # create a DHCP ACK packet to send to the client
        dhcp_ack = Ether(src=get_if_hwaddr(self.interface), dst="ff:ff:ff:ff:ff:ff")/\
                   IP(src=self.subnet, dst="255.255.255.255")/\
                   UDP(sport=67, dport=68)/\
                   BOOTP(op=2, yiaddr=requested_ip, siaddr=self.subnet, chaddr=client_mac)/\
                   DHCP(options=[("message-type", "ack"),
                                  ("subnet_mask", "255.255.255.0"),
                                  ("router", self.subnet),
                                  ("name_server", self.subnet),
                                  ("lease_time", 86400),
                                  "end"])
        return dhcp_ack
    
def get_available_ip():
    subnet = "192.168.1."
    for i in range(1, 255):
        fleg=False
        ip = subnet + str(i)
        for ip_in_pool in ip_pool:
            if ip==ip_in_pool:
             fleg=True 
        if fleg==False:  
            result = os.system("arping -c 1 " + ip)
            if result == 0:
                continue
            else:
                ip_pool.append(ip)                
                return ip
    return None

def main():
    ip_DHCP = get_available_ip()
    if ip_DHCP is not None:
        print("Available DHCP ip:", ip_DHCP)
        dhcp_server = DHCPServer(interface="wlp4s0", subnet=ip_DHCP)
        dhcp_server.start()


    else:
        print("No available IP found.")

if __name__ == "__main__":
    main()


# from scapy.all import *
# ip_pool = []

# DNS_IP='localhost'

# class DHCPServer:
    
#     #Constractor for DHCP server
#     def __init__(self, interface, subnet):
#         self.interface = interface
#         self.subnet = subnet

#     def start(self):
#         # Start the DHCP server and listen for incoming requests in port 67 or 68
#         sniff(prn=self.handle_dhcp_request, filter="udp and (port 67 or 68)", iface=self.interface)

#     def handle_dhcp_request(self, packet):

#         print(f"in if packet[DHCP].options[0][1] {packet[DHCP].options[0][1]}")
#         # Handle DHCP requests and send DHCP responses
#         if DHCP in packet and packet[DHCP].options[0][1] == 1: # DHCP Discover packet
#             print("Get DHCP discover msg")  
#             client_mac = packet[Ether].src
#             requested_ip = get_available_ip()
#             if requested_ip is not None:
#                 dhcp_offer = self.create_dhcp_offer(client_mac, requested_ip,DNS_IP,packet)
#                 sendp(dhcp_offer)
#                 print(f"Send DNS offer msg wish offerIP: {dhcp_offer[0][BOOTP].yiaddr}")
                
#         elif DHCP in packet and packet[DHCP].options[0][1] == 3: # DHCP Request packet
#             print("Get DHCP request msg")
#             client_mac = packet[Ether].src
#             requested_ip = packet[BOOTP].yiaddr
#             dhcp_ack = self.create_dhcp_ack(client_mac, requested_ip,packet)
#             sendp(dhcp_ack)
#             print(f"Send DNS ack msg to client")
        


#     def create_dhcp_offer(self, client_mac, requested_ip,DNS_IP,packet):
#         # create a DHCP Offer packet to send to the client
#         print(f"create_dhcp_offer packet[UDP].sport, {packet[UDP].sport}")
#         dhcp_offer = Ether(src=get_if_hwaddr(self.interface), dst="ff:ff:ff:ff:ff:ff")/\
#                      IP(src=self.subnet, dst="255.255.255.255")/\
#                      UDP(sport=67, dport=68)/\
#                      BOOTP(op=2, yiaddr=requested_ip, siaddr=self.subnet, chaddr=client_mac)/\
#                      DHCP(options=[("message-type", "offer"),
#                                     ("subnet_mask", "255.255.255.0"),
#                                     ("router", self.subnet),
#                                     ("name_server", DNS_IP),
#                                     ("lease_time", 86400),
#                                     "end"])
#         return dhcp_offer

#     def create_dhcp_ack(self, client_mac, requested_ip,packet):
#         # create a DHCP ACK packet to send to the client
#         dhcp_ack = Ether(src=get_if_hwaddr(self.interface), dst="ff:ff:ff:ff:ff:ff")/\
#                    IP(src=self.subnet, dst="255.255.255.255")/\
#                    UDP(sport=67, dport=68)/\
#                    BOOTP(op=2, yiaddr=requested_ip, siaddr=self.subnet, chaddr=client_mac)/\
#                    DHCP(options=[("message-type", "ack"),
#                                   ("subnet_mask", "255.255.255.0"),
#                                   ("router", self.subnet),
#                                   ("name_server", self.subnet),
#                                   ("lease_time", 86400),
#                                   "end"])
#         return dhcp_ack
    
# #Find free ip in the local network 
# def get_available_ip():
#     subnet = "192.168.1."
#     for i in range(1, 255):
#         fleg=False
#         ip = subnet + str(i)
#         for ip_in_pool in ip_pool:
#             if ip==ip_in_pool:
#              fleg=True 
#         if fleg==False:  
#             result = os.system("arping -c 1 " + ip)
#             if result == 0:
#                 continue
#             else:
#                 ip_pool.append(ip)                
#                 return ip
#     return None


# def main():
#     #get free ip for DHCP server
#     ip_DHCP = get_available_ip() 
#     if ip_DHCP is not None:
#         print("Available DHCP ip:", ip_DHCP)
#         dhcp_server = DHCPServer(interface="wlp4s0", subnet=ip_DHCP)
#         dhcp_server.start()
#     else:
#         print("No available IP found.")

# if __name__ == "__main__":
#     main()