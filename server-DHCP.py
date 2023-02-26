import socket

# Define the DHCP server address and port
dhcp_server_address = 'localhost'
dhcp_server_port = 5000

# Define the DNS server address and port
dns_server_address = 'localhost'
dns_server_port = 5001

# Define the application server address and port
app_server_address = 'localhost'
app_server_port = 5002

# Create a socket for the DHCP server
dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dhcp_socket.bind((dhcp_server_address, dhcp_server_port))
dhcp_socket.listen()

while True:
    # Wait for a client to connect
    client_socket, client_address = dhcp_socket.accept()
    print(f'New connection from {client_address}')

    # Receive a message from the client
    client_message = client_socket.recv(1024).decode()
    print(f'Received message from client: {client_message}')

    # Send the IP address of the DNS server to the client
    dhcp_response = dns_server_address
    client_socket.send(dhcp_response.encode())

    # Close the connection to the client
    client_socket.close()