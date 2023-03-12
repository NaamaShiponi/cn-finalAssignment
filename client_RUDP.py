import socket

from scapy.layers.l2 import Ether
from scapy.packet import Raw

address_server = ('localhost', 5000)


def handshake(sock):
    # send SYN message to server
    message = "(SYN) message from client"
    sock.sendto(message.encode(), address_server)
    print(f"message client: {message}")

    # # receive SYN message from server
    # data, address = sock.recvfrom(1024)
    # print(f"message server: {data.decode()}")
    #
    # # send AKE message to server
    # message = "(AKE) Request from client"
    # sock.sendto(message.encode(), address_server)
    # print(f"message client: {message}")


def getSizeFile(sock):
    # send PSH message for size file to server
    message = "(PSH) message for the size of the file on the server"
    sock.sendto(message.encode(), address_server)
    print(f"message client: {message}")

    # receive PSH message size file from server
    data, address = sock.recvfrom(2048)
    data = int.from_bytes(data, 'little', signed=False)
    print(f"message server: (PSH) Request size file: {data}")

    # send AKE message to server
    message = "(AKE) Request from client"
    sock.sendto(message.encode(), address_server)
    print(f"message client: {message}")


def recv_packet(sock):
    # print("recv_packet")
    packet, address = sock.recvfrom(1024)
    # raw_data = recv_pkt[Raw].load
    packet_num = packet.split(b'/')[-1].decode()
    data = packet.split(b'/')[-2].decode()

    return packet_num, data


def send_ack(sock, packet_num):
    message = '/' + str(packet_num)
    print("send massage = " + message)
    sock.sendto(message.encode(), address_server)


def main():
    # create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("sock")

    handshake(sock)
    # getSizeFile(sock)

    file_size = 931905
    file_data = ''

    recv_packet_from_server = {}

    while len(file_data) < file_size:
        packet_num, data = recv_packet(sock)
        if recv_packet_from_server.get(packet_num) is None:
            recv_packet_from_server[packet_num] = data
            file_data += data

        send_ack(sock, packet_num)

    file = open("file_recv_rudp.txt", "w")

    for num in range(len(recv_packet_from_server.keys())):
        file.write(recv_packet_from_server[str(num)])

    file.close()


if __name__ == "__main__":
    main()
