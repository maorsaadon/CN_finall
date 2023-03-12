# Importing necessary modules for packet manipulation
from scapy.all import *
# Importing modules for handling DHCP packets
from scapy.layers.dhcp import DHCP, BOOTP
# Importing modules for handling IP and UDP protocols
from scapy.layers.inet import IP, UDP
# Importing module for handling Ethernet frames
from scapy.layers.l2 import Ether
# imports the socket module which provides a low-level networking interface 
import socket

"""
*************************************************************
                        DHCP client
**************************************************************
"""

class DHCPclient:
    def __init__(self):
        # Get the MAC address of the interface being used
        self.mac_address = get_if_hwaddr(conf.iface)
        # Initialize a variable to hold the IP address assigned by DHCP (not yet known)
        self.ip_address = None
        self.DNSserver_ip= None

    def handle_offer_packet(self,packet):
        # Print a message indicating that an offer packet was received
        print("DHCP offer received")
        # Send a DHCP request packet in response to the offer
        self.send_request_packet(packet)

    def handle_ack_packet(self,ack):
        print("DHCP ack received")
        DNSserver_ip= ack[DHCP].options[5][1]

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

    def send_request_packet(self,offer):
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

class DNSclient:
    def __init__(self):
        # Set the server address and port number
        self.server_address = ('127.0.0.1', 50000)

    def query(self, domain_name):
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server
        client_socket.connect(self.server_address)

        # Encode the domain name and send it to the server
        encoded_query = domain_name.encode()
        client_socket.sendall(encoded_query)

        # Receive the encoded result from the server
        encoded_result = client_socket.recv(1024)

        # Decode the result to get the IP address
        ip_address = encoded_result.decode()

        # Print the IP address
        print("IP address for", domain_name, "is", ip_address)

        # Close the client socket
        client_socket.close()

"""
    *************************************************************
                           HTTP client
    **************************************************************
"""


if __name__ == '__main__':
    
    """
    *************************************************************
                           DHCP request
    **************************************************************
    """

    # Create a DHCPclient object
    dhcp_client = DHCPclient()
    
    # Call the send_discover_packet() function to initiate the DHCP process
    dhcp_client.send_discover_packet()

    """
    *************************************************************
                    DNS query for http-server
    **************************************************************
    """
    
    # Create a DNSclient object
    dns_client = DNSclient()

    # Query the DNS server for the IP address of downloadmanager.com
    dns_client.query("downloadmanager.com")

    """
    *************************************************************
                    request for http-server
    **************************************************************
    """
