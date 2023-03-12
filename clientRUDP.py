# sudo tc qdisc add dev lo root netem loss 20%
# sudo tc qdisc del dev lo root netem

import socket
from scapy.all import *
from time import sleep

from scapy.layers.l2 import Ether
from scapy.packet import Raw


class RUDPClient:

    def __init__(self,ip_server, port_server):
        self.IP_ADDRESS = ip_server
        self.PORT = port_server
        
    def createAndSendPackage(self,sock, packet_num, msg, address_server):
        packet_num=packet_num.to_bytes(1, 'little', signed=False)
        sock.sendto(msg+packet_num,address_server)


    def getMsgAndPM(self,data):
        packet_num = data[-1]
        msg = data[:-1]
        return packet_num,msg



    def receiveData(self,sock, packet_num):
        sock.settimeout(2)
        counter = 0
        
        while True:
            try:
                received_data = sock.recvfrom(2048)
                packet_num_recieved,data= self.getMsgAndPM(received_data[0])
                
                if packet_num_recieved < packet_num:
                    continue
                
                if packet_num != packet_num_recieved:
                    return None, None
                
            except socket.timeout as e:
                err = e.args[0]
                # this next if/else is a bit redundant, but illustrates how the
                # timeout exception is setup
                if err == 'timed out':
                    sleep(1)
                    counter += 1
                    
                    if counter == 2:
                        print("Didn't receive ACK - resend")
                        return None, None
                    continue
                else:
                    print(e)
                    sys.exit(1)
            except socket.error as e:
                # Something else happened, handle error, exit, etc.
                print(e)
                sys.exit(1)       
            return received_data  


    def checkConnection(self,data, sock, packet_num, msg, last_ack):
        
        # Send last ACK
        if last_ack:
            self.createAndSendPackage(sock,last_ack[0],last_ack[1], address_server)
            sleep(0.5)
        
        for c in range(0,2):
                
            if not data:
                self.createAndSendPackage(sock, packet_num+1, msg, address_server)
                data, address_unchecked = self.receiveData(sock, packet_num+2)
            else:
                return data, address_unchecked 
        if data:
            return data, address_unchecked         
        print('Client left the conversation closing the connection')
        sock.close()
        exit()


    def handshake(self,sock, address_server):
        # send SYN message to server
        message = b"(SYN) message from client"
        self.createAndSendPackage(sock, 1, message, address_server)
        print(f"message client:{message.decode()}, package number: 1")
        
        # receive SYN, ACK message from server
        data_unchecked, address_unchecked = self.receiveData(sock,2)

        if not data_unchecked:
            data_unchecked, address_unchecked = self.checkConnection(data_unchecked, sock, 0, message, None)
        data = data_unchecked
        address = address_unchecked
        sock.settimeout(None)
        packet_num,data= self.getMsgAndPM(data)
        
        print(f"message server:{data.decode()}, package number: {packet_num}")

        # send ACK message to server
        message = b"(ACK) Request from client"
        self.createAndSendPackage(sock,packet_num+1,message, address_server)
        print(f"message client:{message.decode()}, package number: {packet_num+1}")


    def getSizeFile(self,sock, address_server):
        # send DATA message for size file to server
        message = b"(DATA) message for the size of the file on the server"
        self.createAndSendPackage(sock, 4, message, address_server)
        last_ack = (4,message)
        print(f"message client:{message.decode()}, package number: 4")

        # receive DATA message size file from server
        # get DATA,ACK message from client
        data_unchecked, address_unchecked = self.receiveData(sock, 5)

        if not data_unchecked:
            data_unchecked, address_unchecked = self.checkConnection(data_unchecked, sock, 4, message, last_ack)
        data = data_unchecked
        address = address_unchecked
        sock.settimeout(None)
        ip, port = self.checkRedirection(sock, data, address_server)
        packet_num,data= self.getMsgAndPM(data)
        if ip:
            return ip,port ,None

        print(f"message server:(DATA,ACK) Request size file: {int(data.decode())}, package number: {packet_num}")
        
        # send ACK message to server
        message = b"(ACK) Request from client"
        self.createAndSendPackage(sock, packet_num+1, message, address_server)
        print(f"message client:{message.decode()}, package number: {packet_num+1}")
        return None, None,int(data.decode())

    def checkRedirection(self,sock, data, address_server):
        packet_num,data= self.getMsgAndPM(data)
        data=data.decode()
        if "RED" in data:
            print(f"message server:{data}, package number: {packet_num}")
            data=data.split(" ")
            ip_address=data[2]
            port=data[3]
            message = b"(ACK) Request from client"
            self.createAndSendPackage(sock, packet_num+1, message, address_server)
            print(f"message client:{message.decode()}, package number: {packet_num+1}")
            return ip_address,int(port)
        return None, None


    def startConv(self,sock, address_server):
        # create a UDP socket
        self.handshake(sock, address_server)
        return self.getSizeFile(sock, address_server)

    def recv_packet(self,sock):
        # print("recv_packet")
        packet, address = sock.recvfrom(1024)
        # raw_data = recv_pkt[Raw].load
        packet_num = packet.split(b'/')[-1].decode()
        data = packet.split(b'/')[-2].decode()

        return packet_num, data


    def send_ack(self,sock, packet_num,address_server):
        message = '/' + str(packet_num)
        sock.sendto(message.encode(), address_server)


    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
        address_server = (self.IP_ADDRESS,self.PORT)
        ip, port, datd= self.startConv(sock, address_server)
        
        while ip:
            address_server = (ip, port)
            print(f"open socket wish {ip} {port}") 
            ip, port ,datd= self.startConv(sock, address_server)  
        
        file_size = datd
        file_data = ''

        recv_packet_from_server = {}
        while len(file_data) < file_size:
            packet_num, data = self.recv_packet(sock)
            if recv_packet_from_server.get(packet_num) is None:
                recv_packet_from_server[packet_num] = data
                file_data += data
                if int(packet_num) ==0:
                    print(f"message server:(DATA) A package was sent from the HTML file , package number: {int(packet_num)+7}")
                    print(f"message client:(ACK) Request from client , package number: {int(packet_num)+8}")
            self.send_ack(sock, packet_num,address_server)
        print(f"\n...The client and the server sent {len(recv_packet_from_server)} packets of (DATA) and (ACK)...\n")

        print(f"message server:(DATA) A package was sent from the HTML file , package number: {int(packet_num)+7}")
        print(f"message client:(ACK) Request from client , packages numbers: {int(packet_num)+8}")

        file = open("file_recv_rudp.html", "w")

        for num in range(len(recv_packet_from_server.keys())):
            file.write(recv_packet_from_server[str(num)])

        file.close()
        
        print("The HTML file has been sent successfully")


    
