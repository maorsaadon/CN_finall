# Importing necessary modules for packet manipulation
from scapy.all import *
# Importing modules for handling DHCP packets
from scapy.layers.dhcp import DHCP, BOOTP
# Importing modules for handling IP and UDP protocols
from scapy.layers.inet import IP, UDP
# Importing module for handling Ethernet frames
from scapy.layers.l2 import Ether
# imports the socket module which provides a low-level networking interface
from flask import Flask, request

import socket as s
import time

"""
*************************************************************
                        DHCP client
**************************************************************
"""


class DHCPClient:
    def __init__(self):
        # Get the MAC address of the interface being used
        self.mac_address = get_if_hwaddr(conf.iface)
        # Initialize a variable to hold the IP address assigned by DHCP (not yet known)
        self.ip_address = None
        self.DNSserver_ip = None

    def handle_offer_packet(self, packet):
        # Print a message indicating that an offer packet was received
        print("DHCP offer received")
        # Send a DHCP request packet in response to the offer
        self.send_request_packet(packet)

    def handle_ack_packet(self, ack):
        print("DHCP ack received")
        self.DNSserver_ip = ack[DHCP].options[5][1]

    def send_discover_packet(self):
        # Construct a DHCP Discover packet using the current MAC address as the client identifier
        discover = Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                   IP(src='0.0.0.0', dst='255.255.255.255') / \
                   UDP(sport=68, dport=67) / \
                   BOOTP(op=1, chaddr=self.mac_address) / \
                   DHCP(options=[('message-type', 'discover'), 'end', 'pad'])
        # Print a message indicating that a Discover packet is being sent
        print("sending DHCP Discover")
        # Send the Discover packet over the network
        sendp(discover)
        # Sniff the network for incoming DHCP offer packets and call handle_offer_packet() when one is received
        sniff(prn=self.handle_offer_packet, filter='(port 67 or port 68)', count=1)

    def send_request_packet(self, offer):
        # Extract the offered IP address from the offer packet and construct a DHCP Request packet
        ip_address = offer[BOOTP].yiaddr
        request = Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                  IP(src='0.0.0.0', dst='255.255.255.255') / \
                  UDP(sport=68, dport=67) / \
                  BOOTP(op=1, chaddr=self.mac_address, yiaddr=ip_address, siaddr=get_if_addr(conf.iface)) / \
                  DHCP(options=[('message-type', 'request'),
                                ('requested_addr', ip_address),
                                ('server_id', offer[DHCP].options[1][1]), 'end', 'pad'])
        # Wait for 1 second before sending the request packet
        time.sleep(1)
        # Print a message indicating that a Request packet is being sent
        print("sending DHCP Request")
        # Send the Request packet over the network
        sendp(request)
        # Sniff the network for incoming DHCP ACK packets and call handle_ack_packet() when one is received
        sniff(prn=self.handle_ack_packet, filter='(port 67 or port 68)', count=1)


"""
*************************************************************
                        DNS client
**************************************************************
"""


class DNSClient:
    def __init__(self):
        # Set the IP address and port number for the DNS server
        self.server_address = ('127.0.0.1', 53)
        self.domain_ip = None

    def query(self, domain):
        # create a UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # construct the DNS query packet
        packet = self.create_dns_packet(domain)

        # send the packet to the DNS server
        client_socket.sendto(packet, self.server_address)

        # receive the response from the DNS server
        response, server_address = client_socket.recvfrom(4096)

        # parse the DNS response packet
        header = response[:12]
        answer_section = response[12 + len(packet):]

        # extract the IP address from the answer section
        ip_bytes = answer_section[-4:]
        self.domain_ip = socket.inet_ntoa(ip_bytes)

        # close the socket
        client_socket.close()

        return self.domain_ip

    def create_dns_packet(self, domain):
        # construct the DNS query packet
        packet = b''
        packet += b'\x00\x01'  # ID
        packet += b'\x01\x00'  # QR=0, Opcode=0, AA=0, TC=0, RD=1
        packet += b'\x00\x01'  # QDCOUNT (1 question)
        packet += b'\x00\x00'  # ANCOUNT
        packet += b'\x00\x00'  # NSCOUNT
        packet += b'\x00\x00'  # ARCOUNT
        # construct the question section
        parts = domain.split('.')
        for part in parts:
            packet += bytes([len(part)])
            packet += part.encode('ascii')
        packet += b'\x00'  # end of domain name
        packet += b'\x00\x01'  # QTYPE=A
        packet += b'\x00\x01'  # QCLASS=IN

        return packet


class TCPClient:
    """
    A simple TCP client implementation
    """

    def __init__(self):
        # Creates a TCP socket
        self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)

    def socket(self):
        return self.sock

    def connect(self, server_ip, server_port):
        try:
            # Connect to the server
            self.sock.connect((server_ip, server_port))
            print(f"Connected to server {server_ip}:{server_port}\n")
        except ConnectionRefusedError as e:
            print(f"Error connecting to server: {e}")
            return False
        return True


DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

BUFFER = 4096
SERVER_PORT = 20000 + DOVI_LAST3_ID_DIG


def client_request(url, file_name):
    """
    *************************************************************
                           DHCP request
    **************************************************************
    """

    # Create a DHCPClient object
    dhcp_client = DHCPClient()

    # Call the send_discover_packet() function to initiate the DHCP process
    dhcp_client.send_discover_packet()

    dns_ip = dhcp_client.DNSserver_ip

    """
    *************************************************************
                    DNS query
    **************************************************************
    """

    # Create a DNSClient object
    dns_client = DNSClient()

    # Query the DNS server for the IP address of downloadmanager.com
    app_server_ip = dns_client.query("downloadmanager.com")
    print('http app domain: downloadmanager.com, http app ip: ' + app_server_ip)
    tcp_c = TCPClient()

    # Connect to the server
    connected = tcp_c.connect(app_server_ip, SERVER_PORT)
    if not connected:
        return

    # Construct the HTTP request
    http_request = f"GET /{file_name} HTTP/1.1\r\nHost: {url}\r\n\r\n".encode()

    # Send the HTTP request to the server
    try:
        tcp_c.socket().send(http_request)
        print("Request sent.\n")
    except ConnectionResetError as e:
        print(f"Error sending request to server: {e}")
        return

    # Receive the HTTP response from the server
    response = b''
    while True:
        try:
            chunk = tcp_c.socket().recv(BUFFER)
        except ConnectionResetError as e:
            print(f"Error receiving response from server: {e}")
            return
        if not chunk:
            break
        response += chunk

    # Deconstruct HTTP response
    response_lines = response.decode('utf-8').split('\r\n')
    status_line = response_lines[0]
    status_code = int(status_line.split()[1])

    if status_code == 200:
        print("HTTP request successful.\n")
    else:
        print(f"HTTP request failed with status code {status_code}\n")
        return

    # Save the file
    print("Saving file...\n")
    try:
        with open(file_name, 'w') as f:
            f.write('\n'.join(response_lines[1:]))
    except IOError as e:
        print(f"Error saving file: {e}")
        return

    print("File successfully saved!\n")


class HTMLFormServer:

    def __init__(self):
        self.app = Flask(__name__)

        @self.app.route('/', methods=['GET', 'POST'])
        def handle_form():
            if request.method == 'POST':
                host_name = request.form['hostName']
                file_name = request.form['fileName']
                client_request(host_name, file_name)
                # Do something with the form data (e.g. print it to the console)
                print("Host Name:", host_name)
                print("File Name:", file_name)
                return "Form submitted successfully"
            else:
                # Serve the HTML file
                return '''
                    <!DOCTYPE html>
                    <html>
                      <head>
                        <meta charset="UTF-8">
                        <title>Web App</title>
                      </head>
                      <body>
                        <form id="myForm" method="post">
                          <label for="hostName">Host Name:</label>
                          <input type="text" id="hostName" name="hostName"><br><br>
                          <label for="fileName">File Name:</label>
                          <input type="text" id="fileName" name="fileName"><br><br>
                          <input type="submit" value="Submit Request">
                        </form>
                      </body>
                    </html>
                '''

    def run(self, host='localhost', port=5000):
        self.app.run(host=host, port=port)


if __name__ == '__main__':
    server = HTMLFormServer()
    server.run()
