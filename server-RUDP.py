import socket
from scapy.all import *
from time import sleep

IP_ADDRESS='localhost'
PORT=5000


def createPackage(sock,packet_num,msg,address):
    packet_num=packet_num.to_bytes(1, 'little', signed=False)
    address_server = (address[0],address[1])
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


def checkConnection(data, sock, packet_num, msg, address, last_ack):
    
    # Send last ACK
    createPackage(sock,last_ack[0],last_ack[1],address)
    sleep(0.5)
    
    for c in range(0,2):
             
        if not data:
            createPackage(sock,packet_num+1,msg,address)
            data, address_unchecked = receiveData(sock, packet_num+2)
        else:
            return data, address_unchecked 
    if data:
        return data, address_unchecked         
    print('Client left the conversation closing the connection')
    sock.close()
    exit()
    
    
def handshake(sock):
    # SYN message from client //1
    data, address = sock.recvfrom(1024)
    packet_num,data= getMsgAndPM(data)
    print(f'message client:{data.decode()}, package number: {packet_num}')

    # Send a response SYN to the client //2
    message = b"(SYN,ACK) Request from server"
    last_ack = (packet_num+1,message)
    createPackage(sock,packet_num+1,message,address)
    print(f'message server:{message.decode()}, package number: {packet_num+1}')

    # get ACK message from client
    data_unchecked, address_unchecked = receiveData(sock,packet_num+2)

    if not data_unchecked:
        data_unchecked, address_unchecked = checkConnection(data_unchecked, sock, packet_num, message, address, last_ack)
    data = data_unchecked
    address = address_unchecked
    sock.settimeout(None)
    
    packet_num,data= getMsgAndPM(data)
    print(f'message client:{data.decode()}, package number: {packet_num}')


def SendSizeFile(sock,file_size): 
    # Message for get size of the file from client
    data, address = sock.recvfrom(1024)
    packet_num,data= getMsgAndPM(data)
    print(f'message client:{data.decode()}, package number: {packet_num}')
    
    message = str(file_size).encode()
    createPackage(sock,packet_num+1,message, address)
    last_ack = (packet_num+1,message)
    
    # Send a response SYN to the client
    print(f'message server:(DATA,ACK) Request size file: {file_size}, package number: {packet_num+1}')
    
    # get ACK message from client
    data_unchecked, address_unchecked = receiveData(sock, packet_num+2)

    if not data_unchecked:
        data_unchecked, address_unchecked = checkConnection(data_unchecked, sock, packet_num, message, address,last_ack)
    data = data_unchecked
    address = address_unchecked
    sock.settimeout(None)
    
    packet_num,data= getMsgAndPM(data)
    print(f'message client:{data.decode()}, package number: {packet_num}')
        
    
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP_ADDRESS, PORT))
    handshake(sock)
    
    with open('example.txt', 'r') as f:
        file_data = f.read()
    
    SendSizeFile(sock,len(file_data))





if __name__ == "__main__":
    main()
