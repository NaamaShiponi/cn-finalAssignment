from scapy.all import *
import socket

from scapy.layers.http import HTTPResponse, HTTP
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

# Create a TCP/IP socket
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to a specific port
server_address = ('', 30760)
print('Starting up on {} port {}'.format(*server_address))
serverSocket.bind(server_address)

# Listen for incoming connections
serverSocket.listen(1)

new_server_address = 'localhost'
new_server_port = 30314

while True:
    # Wait for a connection
    print('Waiting for a connection')
    connection, client_address = serverSocket.accept()

    print('Connection from', client_address)

    # Receive the data in small chunks and retransmit it
    while True:
        pkt = connection.recv(1024)
        print("message client: GET / HTTP/1.1\r\nHost: localhost")
        if pkt:
            # Process packet or reply with another packet
            recv_pkt = Ether(pkt)
            eth_pkt = Ether(src=recv_pkt[Ether].dst, dst=recv_pkt[Ether].src, type=recv_pkt[Ether].type)
            ip_pkt = IP(dst=recv_pkt[IP].src, src=recv_pkt[IP].dst)
            tcp_pkt = TCP(sport=recv_pkt[TCP].dport, dport=recv_pkt[TCP].sport)
            http_pkt = Raw(load="HTTP/1.1 302 Found\r\nLocation: http://" + new_server_address + ":" + str(
                new_server_port) + "/\r\n\r\n")  # Location: https://example.com
            reply = eth_pkt / ip_pkt / tcp_pkt / http_pkt
            connection.sendall(raw(reply))
            print(f"message server: redirection HTTP/1.1 302 Found")
            # Clean up the connection

        else:
            connection.close()
            print('No more data from', client_address)
            break


