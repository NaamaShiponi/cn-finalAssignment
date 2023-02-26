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

# Create a socket for the DNS server
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dns_socket.bind((dns_server_address, dns_server_port))
dns_socket.listen()

while True:
    # Wait for a client to connect
    client_socket, client_address = dns_socket.accept()
    print(f'New connection from {client_address}')

    # Receive a message from the client
    client_message = client_socket.recv(1024).decode()
    print(f'Received message from client: {client_message}')

    # Resolve the DNS query to the IP address of the application server
    if client_message == 'www.example.com':
        dns_response = app_server_address
    else:
        dns_response = 'Unknown domain'

    # Send the IP address of the application server to the client
    client_socket.send(dns_response.encode())

    # Close the connection to the client
    client_socket.close()