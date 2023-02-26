import socket

# Define the DHCP server address and port
dhcp_server_address = 'localhost'
dhcp_server_port = 5000

# Define the DNS server port
dns_server_port = 5001

# Define the application server port
app_server_port = 5002

# Establish a connection to the DHCP server
dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dhcp_socket.connect((dhcp_server_address, dhcp_server_port))

# Send a message to the DHCP server
client_message = 'Hello DHCP Server!'
dhcp_socket.send(client_message.encode())

# Receive a response from the DHCP server with the IP address of the DNS server
dhcp_response = dhcp_socket.recv(1024).decode()

# Close the connection to the DHCP server
dhcp_socket.close()

# Establish a connection to the DNS server
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dns_socket.connect((dhcp_response, dns_server_port))

# Send a message to the DNS server
client_message = 'www.example.com'
dns_socket.send(client_message.encode())

# Receive a response from the DNS server with the IP address of the application server
dns_response = dns_socket.recv(1024).decode()

# Close the connection to the DNS server
dns_socket.close()

# Establish a connection to the application server
app_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
app_socket.connect((dns_response, app_server_port))

# Send a message to the application server
client_message = 'Hello Application Server!'
app_socket.send(client_message.encode())

# Receive a response from the application server
app_response = app_socket.recv(1024).decode()

# Close the connection to the application server
app_socket.close()

# Print the response from the application server
print(app_response)
