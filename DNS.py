import socket

class DNSserver:
    def __init__(self):
        # Set the IP address and port number for the DNS server
        self.ip_address = '127.0.0.1'
        self.port_number = 50000
    
    def DnsHandler(self):
        # Create a socket object
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set socket option to reuse the address
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the IP address and port number
        server_socket.bind((self.ip_address, self.port_number))
        
        # Listen for incoming connections
        server_socket.listen()

        # Handling one client loop
        while True:
            # Accept incoming connections
            client_socket, client_address = server_socket.accept()
            
            # Receive the encoded query from the client
            encoded_query = client_socket.recv(1024)
            
            # Decode the query to get the domain name
            domain_name = encoded_query.decode()
            
            # Initialize the result to an empty string
            result = ""
            
            # Print the query domain name being checked
            print("Checking for the the domain name what is the IP:  " +(domain_name)+ "IP address")
            
            # Check if the query is for 'downloadmanager.com'
            if domain_name == "downloadmanager.com":
                # Set the result to '127.0.0.1' if query is 'downloadmanager.com'
                result = "127.0.0.1".encode()
            else:
                result = self.BuildResponse(domain_name)      
            
            # Send the result to the client
            client_socket.sendall(result)
           
            # Print that the result has been sent
            print("Result has been sent")
    
            # Close the client socket
            client_socket.close()

    def BuildResponse(self, domain_name):
        try:
            # Get the address information for the query domain name
            address_info = socket.getaddrinfo(domain_name, None)
            
            # Extract the IP address from the address information
            encoded_result = address_info[0][4][0]
            
            # Encode the IP address to send to the client
            result = encoded_result.encode()
        except Exception as e:
            # If there is an error, set the result to the error message
            result = str(e).encode()
        return result

# Create a DNS server object and start the server
if __name__ == '__main__':
    
    # Create a DNS server object
    handler = DNSserver()
    
    # Start the DNS server
    handler.DnsHandler()
