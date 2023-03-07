from scapy.all import *
import socket

from scapy.layers.http import HTTPResponse, HTTP
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

# Create a TCP/IP socket
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific port
server_address = ('', 9999)
print('Starting up on {} port {}'.format(*server_address))
serverSocket.bind(server_address)

# Listen for incoming connections
serverSocket.listen(1)

new_server_address = 'localhost'
new_server_port = 9998

while True:
    # Wait for a connection
    print('Waiting for a connection')
    connection, client_address = serverSocket.accept()

    print('Connection from', client_address)

    # Receive the data in small chunks and retransmit it
    while True:
        pkt = connection.recv(1024)
        if pkt:
            print(f"Received Packet:\n{pkt}")
            # Process packet or reply with another packet
            recv_pkt = Ether(pkt)
            eth_pkt = Ether(src=recv_pkt[Ether].dst, dst=recv_pkt[Ether].src, type=recv_pkt[Ether].type)
            ip_pkt = IP(dst=recv_pkt[IP].src, src=recv_pkt[IP].dst)
            tcp_pkt = TCP(sport=recv_pkt[TCP].dport, dport=recv_pkt[TCP].sport)
            http_pkt = Raw(load="HTTP/1.1 302 Found\r\nLocation: http://" + new_server_address + ":" + str(
                new_server_port) + "/\r\n\r\n")  # Location: https://example.com
            reply = eth_pkt / ip_pkt / tcp_pkt / http_pkt
            connection.sendall(raw(reply))
        else:
            print('No more data from', client_address)
            break

    # Clean up the connection
    connection.close()
