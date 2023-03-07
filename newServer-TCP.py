from scapy.all import *
import socket

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific IP address and port
server_address = ('localhost', 9998)
print('Starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

with open('example.txt', 'r') as f:
    file_data = f.read()

while True:
    # Wait for a connection
    print('Waiting for a connection')
    connection, client_address = sock.accept()
    try:
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
                tcp_pkt = TCP(sport=recv_pkt[TCP].dport, dport=recv_pkt[TCP].sport, flags="SA")
                http_pkt = Raw(load="HTTP/1.1 200 OK/\r\n\r\n")
                reply = eth_pkt / ip_pkt / tcp_pkt / http_pkt
                connection.sendall(raw(reply))

                raw_pkt_len = Raw(load=str(len(file_data)))
                len_file_reply = eth_pkt / ip_pkt / tcp_pkt / raw_pkt_len
                connection.sendall(raw(len_file_reply))

                pkt = connection.recv(1024)

                raw_pkt_file = Raw(load=file_data)
                file_reply = eth_pkt / ip_pkt / tcp_pkt / raw_pkt_file
                connection.sendall(raw(file_reply))

            else:
                print('No more data from', client_address)
                break

    finally:
        # Clean up the connection
        connection.close()



