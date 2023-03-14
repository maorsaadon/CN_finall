import socket


class DNSserver: 
    def __init__(self):
        self.ip_domain = None
        self.addresses = {}

    def recieve_dns_query(self):
        # create a UDP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # bind the socket to a local address and port
        server_socket.bind(('127.0.0.1', 53))

        while True:
            # receive a DNS query packet
            query_packet, client_address = server_socket.recvfrom(4096)

            # construct the DNS response packet
            response_packet = self.handle_query_response(query_packet)

            # send the response packet to the client
            server_socket.sendto(response_packet, client_address)

    def handle_query_response(self, query_packet):
        """
        Given a DNS query packet, construct a DNS response packet and return it.
        """
        # extract the domain name from the query packet
        domain = self.extract_domain(query_packet)

        # resolve the IP address for the domain name
        if domain in self.addresses:
            self.ip_domain = self.addresses[domain]
            print(f"Resolved {domain} to {self.ip_domain}, using our Database module. ")
        else:
            self.ip_domain = socket.gethostbyname(domain)
            print(f"Resolved {domain} -> {self.ip_domain}, using the socket module.")
           
        # construct the DNS response packet
        packet = b''
        packet += query_packet[:2]  # copy the ID from the query packet
        packet += b'\x81\x80'  # QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=0
        packet += query_packet[4:6]  # copy the QDCOUNT from the query packet
        packet += b'\x00\x01'  # ANCOUNT=1
        packet += b'\x00\x00'  # NSCOUNT=0
        packet += b'\x00\x00'  # ARCOUNT=0
        # construct the question section
        packet += query_packet[12:]
        # construct the answer section
        packet += b'\xc0\x0c'  # pointer to the domain name in the question section
        packet += b'\x00\x01'  # TYPE=A
        packet += b'\x00\x01'  # CLASS=IN
        packet += b'\x00\x00\x01\x2c'  # TTL=300 seconds
        packet += b'\x00\x04'  # RDLENGTH=4 bytes
        packet += socket.inet_aton(self.ip_domain)

        return packet

    def extract_domain(self,query_packet):
        """
        Given a DNS query packet, extract the domain name from the question section
        and return it.
        """
        domain = ''
        pos = 12
        while query_packet[pos] != 0:
            length = query_packet[pos]
            domain += query_packet[pos+1:pos+1+length].decode('ascii') + '.'
            pos += 1 + length
        domain = domain[:-1]  # remove the trailing dot
        return domain


if __name__ == '__main__':
    # create a DNS server instance
    dns_server = DNSserver()
    dns_server.addresses = {'downloadmanager.com': '127.0.0.1'}

    # listen for incoming DNS queries and handle them
    dns_server.recieve_dns_query()
