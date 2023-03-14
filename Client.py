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

import random
import struct
import socket as s
import time

DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

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


"""
    *************************************************************
                           RUDP client
    *************************************************************
"""

# Constants
CHUNK = 2048  # Maximum data size in packet
HEADER_SIZE = 8  # Size of packet header
ATTEMPT_LIMIT = 10
DATA_PACKET = 0  # Packet type for data packets
ACK_PACKET = 1  # Packet type for acknowledgement packets
SYN_PACKET = 2  # Packet type for syn packet
SYN_ACK_PACKET = 3  # Packet type for syn ack packet
FILE_SIZE_INFO = 4  # a special packet type for indicating the file size to be sent.
CLOSE_CONNECTION = 5  # Packet type for closing connection
REQUEST_PACKET = 7
REQUEST_ACK = 8
FORMAT = '!II'  # format string for struct.pack and struct.unpack
TIMEOUT = 2


def deconstruct_packet(packet):
    seq, packet_type = struct.unpack(FORMAT, packet[0][:HEADER_SIZE])
    return {'type': packet_type, 'seq': seq, 'src_address': packet[1], 'data': packet[0][HEADER_SIZE:]}


class RUDPClient:
    def __init__(self):
        """
        Constructor for the ReliableUDP class
        :param host_adress: port and ip
        :param server: boolean flag indicating whether this instance is running as a server or client
        """
        self.sock = s.socket(s.AF_INET, s.SOCK_DGRAM)  # Create a UDP socket
        self.sock.setblocking(False)  # Set socket to non-blocking mode
        self.sock.settimeout(TIMEOUT)  # Set socket timeout to 1 second
        self.received_packets = {}  # Dictionary for holding received data payloads
        self.outgoing_seq = random.randint(0, (2 ** 16))  # Sequence number for outgoing packets
        self.server_address = None  # tuple: (ip, port)
        self.all_data_received = False
        self.request_sent = False

    def connect(self, server_ip, server_port):
        self.server_address = server_ip, server_port
        for i in range(ATTEMPT_LIMIT):
            # create a SYN packet
            syn_packet = struct.pack(FORMAT, self.outgoing_seq, SYN_PACKET)
            # send the SYN packet to the server
            self.sock.sendto(syn_packet, (server_ip, server_port))

            time.sleep(2)  # 2 seconds grace period

            # receive syn ack
            try:
                # wait for SYN-ACK response from server
                type, seq, address, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                # verify that the packet is a SYN-ACK packet
                if type == SYN_ACK_PACKET:
                    # send ACK packet to server
                    print("Connection with server established...\n")
                    return True
            except socket.timeout:
                self.outgoing_seq += 1
        self.server_address = None
        return False

    def send_request(self, request):
        attempts = 10
        while attempts > 0 and not self.request_sent:
            try:
                http_request_packet = struct.pack(FORMAT, self.outgoing_seq, REQUEST_PACKET)
                self.outgoing_seq += 1
                http_request_packet += request
                self.sock.sendto(http_request_packet, self.server_address)
                self.request_sent = True
                self.receive_data()
            except TypeError:
                attempts -= 1
                continue
        if not self.request_sent:
            print("Something went Wrong! Could not send request....")
            self.sock.close()

    def receive_data(self):
        packets_to_be_received = float('inf')
        while not self.all_data_received:
            try:
                type, seq, address, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                if type == DATA_PACKET:
                    self.received_packets[seq] = {'src address': address, 'data': data}
                    packets_to_be_received -= 1
                    self.ack(seq)
                    print(f"Downloaded pakcet - {seq} : {data}\n")
                elif type == FILE_SIZE_INFO:
                    self.received_packets[seq] = {'src address': address, 'data': data}
                    packets_to_be_received = int(data.decode()[19:]) - len(self.received_packets)
                    self.ack(seq)
                    print(f"Received file size info. file size to be downloaded is: {packets_to_be_received}\n")
                elif packets_to_be_received == 0 and type == CLOSE_CONNECTION:
                    self.received_packets[seq] = {'src address': address, 'data': b'CLOSE CONNECTION'}
                    self.outgoing_seq += 1
                    self.ack(seq)
                    self.all_data_received = True
                    break

                else:  # type == REQUEST_ACK:
                    self.received_packets[seq] = {'src address': address, 'data': b'REQUEST ACK'}
                    self.request_sent = True
                    print("Request received by server...\n")
            except socket.timeout:
                if packets_to_be_received == 0:
                    self.all_data_received = True
                    break
                continue
        self.sock.close()

    def ack(self, seq):
        """
        Sends an acknowledgement packet for a specified sequence number to the src address
        :param seq: the sequence number of the packet to acknowledge
        """
        ack = struct.pack(FORMAT, self.outgoing_seq, ACK_PACKET)
        ack += f"ACK: {seq}".encode()
        self.sock.sendto(ack, self.received_packets[seq]['src address'])
        self.outgoing_seq += 1


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

    """
    *************************************************************
                        HTTP request
    **************************************************************
    """

    rudp_c = RUDPClient()
    rudp_c.connect(app_server_ip, 20000 + DOVI_LAST3_ID_DIG)

    http_request = f"GET /{file_name} HTTP/1.1\r\nHost: {url}\r\n\r\n".encode()

    rudp_c.send_request(http_request)

    if not rudp_c.request_sent:
        return

    print("Preparing to download file...\n")

    rudp_c.receive_data()

    if rudp_c.all_data_received:
        print("File downloaded. Preparing file.\n")
        data = b''
        packets = sorted(rudp_c.received_packets.items(), key=lambda item: item[0])

        for i in range(len(packets)):
            data += packets[i][1]['data']
        output = data.decode('utf-8')

        print("Saving file...\n")
        with open(file_name, 'w') as f:
            f.write(output)
        print("File successfuly saved!\n")
        print("Closing Connection with server...\n")
    else:
        print("Something went wrong!")


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
