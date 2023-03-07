from scapy.all import *
import socket
from scapy.layers.http import HTTPRequest, HTTP, HTTPResponse
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


def create_packet(server_address):
    http_payload = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    pkt = Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff') / IP(src='localhost', dst=server_address[0]) / TCP(
        sport=1234, dport=server_address[1]) / http_payload
    return pkt


def create_ACK_packet(server_address):
    http_payload = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    pkt = Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff') / IP(src='localhost', dst=server_address[0]) / TCP(
        sport=1234, dport=server_address[1], flags="SA")
    return pkt


def send_packet(sock, pkt, address):
    print('send packet to {} port {}'.format(*address))
    sock.sendall(raw(pkt))


def receive_packet(sock):
    reply = sock.recv(1024)
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


def main():
    server_address = ('localhost', 9999)
    sock = connect_to_server(server_address)

    try:
        pkt = create_packet(server_address)
        send_packet(sock, pkt, server_address)
        recv_pkt = receive_packet(sock)
        status_code = extract_status_code(recv_pkt)

        if status_code == '302':

            new_address = extract_new_address(recv_pkt)

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


if __name__ == '__main__':
    main()
