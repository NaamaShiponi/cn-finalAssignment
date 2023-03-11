# sudo tc qdisc add dev lo root netem loss 20%
# sudo tc qdisc del dev lo root netem

import socket
from scapy.all import *
from time import sleep

# Constants
IP_ADDRESS='localhost'
PORT=5001

def createAndSendPackage(sock, packet_num, msg, address_server):
    packet_num=packet_num.to_bytes(1, 'little', signed=False)
    sock.sendto(msg+packet_num,address_server)


def getMsgAndPM(data):
    packet_num = data[-1]
    msg = data[:-1]
    return packet_num,msg



def receiveData(sock, packet_num):
    sock.settimeout(2)
    counter = 0
    
    while True:
        try:
            received_data = sock.recvfrom(2048)
            packet_num_recieved,data= getMsgAndPM(received_data[0])
            
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


def checkConnection(data, sock, packet_num, msg, last_ack):
    
    # Send last ACK
    if last_ack:
        createAndSendPackage(sock,last_ack[0],last_ack[1], address_server)
        sleep(0.5)
    
    for c in range(0,2):
             
        if not data:
            createAndSendPackage(sock, packet_num+1, msg, address_server)
            data, address_unchecked = receiveData(sock, packet_num+2)
        else:
            return data, address_unchecked 
    if data:
        return data, address_unchecked         
    print('Client left the conversation closing the connection')
    sock.close()
    exit()


def handshake(sock, address_server):
    # send SYN message to server
    message = b"(SYN) message from client"
    createAndSendPackage(sock, 1, message, address_server)
    print(f"message client:{message.decode()}, package number: 1")
    
    # receive SYN, ACK message from server
    data_unchecked, address_unchecked = receiveData(sock,2)

    if not data_unchecked:
        data_unchecked, address_unchecked = checkConnection(data_unchecked, sock, 0, message, None)
    data = data_unchecked
    address = address_unchecked
    sock.settimeout(None)
    packet_num,data= getMsgAndPM(data)
    
    print(f"message server:{data.decode()}, package number: {packet_num}")

    # send ACK message to server
    message = b"(ACK) Request from client"
    createAndSendPackage(sock,packet_num+1,message, address_server)
    print(f"message client:{message.decode()}, package number: {packet_num+1}")


def getSizeFile(sock, address_server):
    # send DATA message for size file to server
    message = b"(DATA) message for the size of the file on the server"
    createAndSendPackage(sock, 4, message, address_server)
    last_ack = (4,message)
    print(f"message client:{message.decode()}, package number: 4")

    # receive DATA message size file from server
    # get DATA,ACK message from client
    data_unchecked, address_unchecked = receiveData(sock, 5)

    if not data_unchecked:
        data_unchecked, address_unchecked = checkConnection(data_unchecked, sock, 4, message, last_ack)
    data = data_unchecked
    address = address_unchecked
    sock.settimeout(None)
    ip, port = checkRedirection(sock, data, address_server)
    packet_num,data= getMsgAndPM(data)
    if ip:
        return ip,port
    print(f"message server:(DATA,ACK) Request size file: {data.decode()}, package number: {packet_num}")
    
    # send ACK message to server
    message = b"(ACK) Request from client"
    createAndSendPackage(sock, packet_num+1, message, address_server)
    print(f"message client:{message.decode()}, package number: {packet_num+1}")
    return None, None

def checkRedirection(sock, data, address_server):
    packet_num,data= getMsgAndPM(data)
    data=data.decode()
    if "RED" in data:
        print(f"message server:{data}, package number: {packet_num}")
        data=data.split(" ")
        ip_address=data[2]
        port=data[3]
        message = b"(ACK) Request from client"
        createAndSendPackage(sock, packet_num+1, message, address_server)
        print(f"message client:{message.decode()}, package number: {packet_num+1}")
        return ip_address,int(port)
    return None, None


def startConv(sock, address_server):
    # create a UDP socket
    handshake(sock, address_server)
    return getSizeFile(sock, address_server)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
    address_server = (IP_ADDRESS,PORT)
    ip, port = startConv(sock, address_server)
    
    while ip:
        address_server = (ip, port)
        print(f"open socket wish {ip} {port}") 
        ip, port = startConv(sock, address_server)  
             
    
    
if __name__ == "__main__":
    main()