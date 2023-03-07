import socket

DNS_IP = '127.0.0.1'
DNS_PORT = 53


def query_dns(query):
    # Create a UDP socket for sending and receiving data
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send the DNS query to the server
    sock.sendto(query, (DNS_IP, DNS_PORT))

    # Receive the response from the server
    response, server_address = sock.recvfrom(4096)

    # Close the socket
    sock.close()

    return response


def build_query(domain):
    # Create a DNS query for an A record for the given domain
    query = b''
    domain_parts = domain.split('.')

    for part in domain_parts:
        query += bytes([len(part)]) + part.encode('utf-8')

    query += b'\x00\x00\x01\x00\x01'

    return query


# Example usage:
query = build_query('example.com')
response = query_dns(query)
print(response)
