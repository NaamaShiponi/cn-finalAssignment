from scapy.all import *
import socket
from scapy.layers.http import HTTPRequest, HTTP, HTTPResponse
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

class TCPClient:

    def __init__(self,ip_server, port_server):
        self.IP_ADDRESS = ip_server
        self.PORT = port_server
        
    def create_packet(self,server_address):
        http_payload = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
        pkt = Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff') / IP(src='localhost', dst=server_address[0]) / TCP(
            sport=20314, dport=server_address[1]) / http_payload
        return pkt


    def create_ACK_packet(self,server_address):
        pkt = Ether(src='11:22:33:44:55:66', dst='aa:bb:cc:dd:ee:ff') / IP(src='localhost', dst=server_address[0]) / TCP(
            sport=20314, dport=server_address[1], flags="SA")
        return pkt


    def send_packet(self,sock, pkt, address):
        print('send packet to {} port {}'.format(*address))
        sock.sendall(raw(pkt))


    def receive_packet(self,sock):
        reply = sock.recv(1024)
        recv_pkt = Ether(reply)
        return recv_pkt


    def extract_status_code(self,recv_pkt):
        if HTTPResponse in recv_pkt:
            http_response = HTTPResponse(recv_pkt[Raw])
            status_code = http_response.Status_Line.split()[1]
        else:
            raw_data = recv_pkt[Raw].load
            status_code = raw_data.split(b'\r\n')[0].split(b' ')[1].decode()
        return status_code


    def extract_new_address(self,recv_pkt):
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


    def extract_new_address_and_port(self,new_address):
        address_and_port = new_address.split('/')[2]
        port_ind = address_and_port.find(':')
        new_port = address_and_port[port_ind + 1:]
        new_address = address_and_port[:port_ind]
        return new_address, new_port


    def connect_to_server(self,address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost',20314))
        sock.connect(address)
        return sock


    def close_socket(self,sock, server_address):
        print(f"Closed socket at {server_address}")
        sock.close()


    def start(self):
        server_address = (self.IP_ADDRESS, self.PORT)
        sock = self.connect_to_server(server_address)

        try:
            pkt = self.create_packet(server_address)
            self.send_packet(sock, pkt, server_address)
            recv_pkt = self.receive_packet(sock)
            status_code = self.extract_status_code(recv_pkt)

            if status_code == '302':

                new_address = self.extract_new_address(recv_pkt)

                if new_address is not None:

                    new_server_address, new_server_port = self.extract_new_address_and_port(new_address)
                    self.close_socket(sock, server_address)  # close the old server

                    new_address = (new_server_address, int(new_server_port))

                    sock = self.connect_to_server(new_address)  # open the new server

                    # make and send a HTTP GET Request
                    pkt = self.create_packet(server_address)
                    self.send_packet(sock, pkt, new_address)

                    # recv and check status_code
                    recv_pkt = self.receive_packet(sock)
                    status_code = self.extract_status_code(recv_pkt)
                    if status_code == '200':
                        # create and send ack packet for the size file
                        ack_pkt = self.create_ACK_packet(server_address)
                        self.send_packet(sock, ack_pkt, new_address)

                    print("bigen to recv file data")
                    reply1 = 0
                    file = open("new_file.txt", "w")

                    while True:
                        reply = sock.recv(4096).decode()
                        if "END FILE" in reply:
                            # print(str(reply1))
                            print("END FILE RECV")
                            break
                        reply1 += len(reply)
                        file.write(reply)

                    print("finish")
                    file.close()

                else:
                    print("Could not extract new server address from HTTP response packet")

        except (socket.error, socket.timeout) as e:
            print(f"An error occurred while sending/receiving data: {e}")

        except KeyboardInterrupt:
            print("Program interrupted by user")

        finally:
            self.close_socket(sock, server_address)
            print('Closing socket')



