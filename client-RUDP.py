
import socket
address_server = ('localhost', 5000)
def handshake(sock):
    # send SYN message to server
    message = "(SYN) message from client"
    sock.sendto(message.encode(), address_server)
    print(f"message client: {message}")
    
    # receive SYN message from server
    data, address = sock.recvfrom(1024)
    print(f"message server: {data.decode()}")

    # send AKE message to server
    message = "(AKE) Request from client"
    sock.sendto(message.encode(), address_server)
    print(f"message client: {message}")


def getSizeFile(sock):
    # send PSH message for size file to server
    message = "(PSH) message for the size of the file on the server"
    sock.sendto(message.encode(), address_server)
    print(f"message client: {message}")

    
    # receive PSH message size file from server
    data, address = sock.recvfrom(2048)
    data=int.from_bytes(data, 'little', signed=False)
    print(f"message server: (PSH) Request size file: {data}")
    
    # send AKE message to server
    message = "(AKE) Request from client"
    sock.sendto(message.encode(), address_server)
    print(f"message client: {message}")

    
    

def main():
    # create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    handshake(sock)
    getSizeFile(sock)
    
    
if __name__ == "__main__":
    main()