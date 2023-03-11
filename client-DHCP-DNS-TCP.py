from scapy.all import *
import random
import uuid
import socket
from scapy.layers.http import HTTPRequest, HTTP, HTTPResponse
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


ip_client="0.0.0.0"

mac_addr = "08:00:27:56:58:68" # MAC address of the client

xid = random.randint(1, 100000) # Transaction ID

DNS_SERVER_PORT = 52

recvSize=1024

#Create dhcp discover packet 
def create_dhcp_discover(mac_addr,xid):
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_addr)/\
                IP(src="0.0.0.0", dst="255.255.255.255")/\
                UDP(sport=68, dport=67)/\
                BOOTP(chaddr=mac_addr, xid=xid)/\
                DHCP(options=[("message-type", "discover"),
                              "end"])
    return dhcp_discover

#Create dhcp request packet 
def create_dhcp_request(mac_addr,xid,ip_client):
    dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_addr)/\
                IP(src="0.0.0.0", dst="255.255.255.255")/\
                UDP(sport=68, dport=67)/\
                BOOTP(chaddr=mac_addr, xid=xid)/\
                DHCP(options=[("message-type", "request"),
                               ("server_id", "192.168.1.100"),
                               ("requested_addr", ip_client),
                               "end"])
    return dhcp_request

#Create dns request packet send and return the respons
def create_dns_request(domain_name,DNS_SERVER_IP,DNS_SERVER_PORT):
    dns_query = IP(dst=DNS_SERVER_IP)/\
                UDP(dport=DNS_SERVER_PORT)/\
                DNS(rd=1,qd=DNSQR(qname=domain_name))

    # Send the query to the DNS server and wait for a response
    return sr1(dns_query)


   
def dhcp_dns():
    
    #Create dhcp discover packet
    dhcp_discover= create_dhcp_discover(mac_addr,xid)

    # Send the DHCP Discover packet and wait for a response
    sendp(dhcp_discover)

    dhcp_discover = sniff(filter="udp and (port 67 or 68)",timeout=3, iface="wlp4s0")

    if len(dhcp_discover) > 0:
        print("Received DHCP response:")
        # dhcp_response[0].show()
        ip_client = dhcp_discover[0][BOOTP].yiaddr
        ip_dns=dhcp_discover[0][DHCP].options[3][1]
        
        print("offer IP fron dhcp ",ip_client)

        print("dns ip ",ip_dns)
    else:
        print("No response received")
        

    # Construct the DHCP request packet
    dhcp_request= create_dhcp_request(mac_addr,xid,ip_client)

    # Send the DHCP request packet and wait for a response
    sendp(dhcp_request)

    # Sniffer to port 67 or 68 requests
    dhcp_response = sniff(filter="udp and (port 67 or 68)", timeout=1, iface="wlp4s0")

    #get domain 
    domain_name = input("Enter the domain to lookup (e.g. www.server-RUDP.com/www.server-TCP.com): ")
    
    response=create_dns_request(domain_name,ip_dns,DNS_SERVER_PORT)
    
    # Extract the IP address from the response and print it
    ip_address = response[DNS].an.rdata
    print(f'{domain_name} has IP address: {ip_address}')
    
    return ip_address ,domain_name

#Create HTTP GET packet
def create_packet(server_address):
    http_payload = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    pkt = Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff') / IP(src='localhost', dst=server_address[0]) / TCP(
        sport=1234, dport=server_address[1]) / http_payload
    return pkt

#Create ACK to HTTP GET packet
def create_ACK_packet(server_address):
    http_payload = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    pkt = Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff') / IP(src='localhost', dst=server_address[0]) / TCP(
        sport=1234, dport=server_address[1], flags="SA")
    return pkt


def send_packet(sock, pkt, address):
    print('send packet to {} port {}'.format(*address))
    sock.sendall(raw(pkt))


def receive_packet(sock):
    reply = sock.recv(recvSize)
    recv_pkt = Ether(reply)
    return recv_pkt


def extract_status_code(recv_pkt):
    if HTTPResponse in recv_pkt:
        http_response = HTTPResponse(recv_pkt[Raw])
        status_code = http_response.Status_Line.split()[1]
    else:
        raw_data = recv_pkt[Raw].load
        status_code = raw_data.split(b'\r\n')[0].split(b' ')[1].decode()
    return status_code


def extract_new_address(recv_pkt):
    if HTTPResponse in recv_pkt:
        new_address = recv_pkt.fields['Location'].decode()
    else:
        raw_data = recv_pkt[Raw].load
        for line in raw_data.split(b'\r\n'):
            if line.startswith(b'Location:'):
                new_address = line.split(b' ')[1].decode()
                break
        else:
            new_address = None

        return new_address


def extract_new_address_and_port(new_address):
    address_and_port = new_address.split('/')[2]
    port_ind = address_and_port.find(':')
    new_port = address_and_port[port_ind + 1:]
    new_address = address_and_port[:port_ind]
    return new_address, new_port


def connect_to_server(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(address)
    return sock


def close_socket(sock, server_address):
    print(f"Closed socket at {server_address}")
    sock.close()


def tcpClint(server_address):
    sock = connect_to_server(server_address)

    try:
        pkt = create_packet(server_address)
        send_packet(sock, pkt, server_address)
        recv_pkt = receive_packet(sock)
        status_code = extract_status_code(recv_pkt)

        if status_code == '302':

            new_address = extract_new_address(recv_pkt)

            q=Ether(recv_pkt)
            
            if new_address is not None:
                new_server_address, new_server_port = extract_new_address_and_port(new_address)
                close_socket(sock, server_address)
                new_address = (new_server_address, int(new_server_port))
                sock = connect_to_server(new_address)
                pkt = create_packet(server_address)
                send_packet(sock, pkt, new_address)
                recv_pkt = receive_packet(sock)
                recv_pkt = receive_packet(sock)
                ack_pkt = create_ACK_packet(server_address)
                send_packet(sock, ack_pkt, new_address)
                len_data = int(recv_pkt[Raw].load.decode())
                recv_pkt = receive_packet(sock)
                data = recv_pkt[Raw].load.decode()

                while len(data) < len_data-42:
                    recv_pkt = receive_packet(sock)
                    data += recv_pkt[Raw].load.decode()
                print("finish")
            else:
                print("Could not extract new server address from HTTP response packet")

    except (socket.error, socket.timeout) as e:
        print(f"An error occurred while sending/receiving data: {e}")

    except KeyboardInterrupt:
        print("Program interrupted by user")

    finally:
        close_socket(sock, server_address)
        print('Closing socket')

def rudoClint(server_address):
    return
def main():
    
    #Start connection wish dhcp and dns
    ip_server,domain_name=dhcp_dns()
    
    
    if "TCP" in (str)(domain_name):
        port_server=9999
        #Create the TCP server address
        server_address = (ip_server, port_server)
        tcpClint(server_address)
    if "RUDP" in (str)(domain_name):
        port_server=5001
        #Create the RUDP server address
        server_address = (ip_server, port_server)
        rudoClint(server_address)

    
    
    
   

if __name__ == "__main__":
    main()