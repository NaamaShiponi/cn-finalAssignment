from scapy.all import *
import socket

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

def build_packet(recv_pkt_from_client, str_to_send):
    eth_pkt = Ether(src=recv_pkt_from_client[Ether].dst, dst=recv_pkt_from_client[Ether].src, type=recv_pkt_from_client[Ether].type)
    ip_pkt = IP(dst=recv_pkt_from_client[IP].src, src=recv_pkt_from_client[IP].dst)
    tcp_pkt = TCP(sport=recv_pkt_from_client[TCP].dport, dport=recv_pkt_from_client[TCP].sport, flags="SA")
    http_pkt = Raw(load=str_to_send)
    ryple_packet = eth_pkt / ip_pkt / tcp_pkt / http_pkt
    # ryple_packet.show()

    return ryple_packet

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
                recv_pkt = Ether(pkt)

                # create and send HTTP OK Response
                str_raw = "HTTP/1.1 200 OK/\r\n\r\n"
                reply = build_packet(recv_pkt, str_raw)
                connection.sendall(raw(reply))

                # wait for ACK that the server recv the HTTPRe
                pkt = connection.recv(1024)

                # create and send the file
                # file_reply = build_packet(recv_pkt, file_data)
                connection.send(file_data.encode())
                # end_file_reply = build_packet(recv_pkt, "END FILE")
                print("END FILE")
                end_file_reply = "END FILE"
                connection.send(end_file_reply.encode())

            else:
                print('No more data from', client_address)
                break

    finally:
        # Clean up the connection
        connection.close()



