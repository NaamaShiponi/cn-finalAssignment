import socket
from scapy.all import *

def handshake(sock):
    # SYN message from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data}')

    # Send a response SYN to the client
    response = "(SYN) Request from server"
    sock.sendto(response.encode(), address)
    print(f'message server:  {response}')

    # get AKE message from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data}')

def SendSizeFile(sock):
    # Message for get size of the file from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data} ')

    # Check the size of the file
    sizeFile=1
    data=sizeFile.to_bytes(2, 'little', signed=False)

    # Send a response SYN to the client
    sock.sendto(data, address)
    print(f'message server:  (PSH) Request size file:{sizeFile}')

    
    # get AKE message from client
    data, address = sock.recvfrom(1024)
    print(f'message client:{data}')
    
    
    
def main():
    app_server_address = 'localhost'
    app_server_port = 5000
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((app_server_address, app_server_port))

    handshake(sock)
    SendSizeFile(sock)

if __name__ == "__main__":
    main()
