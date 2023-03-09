# sudo tc qdisc add dev lo root netem loss 20%
#sudo tc qdisc del dev lo root netem

import socket
from scapy.all import *
from time import sleep

# Constants
IP_ADDRESS='localhost'
PORT=5000
address_server = (IP_ADDRESS,PORT)

def createPackage(sock,packet_num,msg):
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
        createPackage(sock,last_ack[0],last_ack[1])
        sleep(0.5)
    
    for c in range(0,2):
             
        if not data:
            createPackage(sock,packet_num+1,msg)
            data, address_unchecked = receiveData(sock, packet_num+2)
        else:
            return data, address_unchecked 
    if data:
        return data, address_unchecked         
    print('Client left the conversation closing the connection')
    sock.close()
    exit()


def handshake(sock):
    # send SYN message to server
    message = b"(SYN) message from client"
    createPackage(sock,1,message)
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
    createPackage(sock,packet_num+1,message)
    print(f"message client:{message.decode()}, package number: {packet_num+1}")


def getSizeFile(sock):
    # send DATA message for size file to server
    message = b"(DATA) message for the size of the file on the server"
    createPackage(sock,4,message)
    last_ack = (4,message)
    print(f"message client:{message.decode()}, package number: 4")

    # receive DATA message size file from server
    # get DATA,ACK message from client
    data_unchecked, address_unchecked = receiveData(sock,5)

    if not data_unchecked:
        data_unchecked, address_unchecked = checkConnection(data_unchecked, sock, 4, message, last_ack)
    data = data_unchecked
    address = address_unchecked
    sock.settimeout(None)
    
    packet_num,data= getMsgAndPM(data)
    # data=int.from_bytes(data, 'little', signed=False)
    print(f"message server:(DATA,ACK) Request size file: {data.decode()}, package number: {packet_num}")
    
    # send ACK message to server
    message = b"(ACK) Request from client"
    createPackage(sock,packet_num+1,message)
    print(f"message client:{message.decode()}, package number: {packet_num+1}")

    
def main():
    # create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
    handshake(sock)
    getSizeFile(sock)
    
    
if __name__ == "__main__":
    main()