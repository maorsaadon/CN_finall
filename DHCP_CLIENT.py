# Importing necessary modules for packet manipulation
from scapy.all import *
# Importing modules for handling DHCP packets
from scapy.layers.dhcp import DHCP, BOOTP
# Importing modules for handling IP and UDP protocols
from scapy.layers.inet import IP, UDP
# Importing module for handling Ethernet frames
from scapy.layers.l2 import Ether

# Get the MAC address of the interface being used
mac_address = get_if_hwaddr(conf.iface)
 # Initialize a variable to hold the IP address assigned by DHCP (not yet known)
ip_address = None
 

def handle_offer_packet(packet):
    # Print a message indicating that an offer packet was received
    print("DHCP offer received")
     # Send a DHCP request packet in response to the offer
    send_request_packet(packet)

def handle_ack_packet(packet):
    # Print a message indicating that an ACK packet was received
    print("DHCP ack received")

def send_discover_packet():
     # Construct a DHCP Discover packet using the current MAC address as the client identifier
    discover = Ether(src=mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                IP(src='0.0.0.0', dst='255.255.255.255') / \
                UDP(sport=68, dport=67) / \
                BOOTP(op=1, chaddr=mac_address) / \
                DHCP(options=[('message-type', 'discover'), 'end', 'pad'])
    # Print a message indicating that a Discover packet is being sent
    print("sending DHCP Discover")
     # Send the Discover packet over the network
    sendp(discover)
     # Sniff the network for incoming DHCP offer packets and call handle_offer_packet() when one is received
    sniff(prn=handle_offer_packet, filter='(port 67 or port 68)', count=1)

def send_request_packet(offer):
    # Extract the offered IP address from the offer packet and construct a DHCP Request packet
    ip_address = offer[BOOTP].yiaddr
    request = Ether(src=mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                IP(src='0.0.0.0', dst='255.255.255.255') / \
                UDP(sport=68, dport=67) / \
                BOOTP(op=1, chaddr=mac_address, yiaddr=ip_address, siaddr=get_if_addr(conf.iface)) / \
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
    sniff(prn=handle_ack_packet, filter='(port 67 or port 68)', count=1)

# Call the send_discover_packet() function to initiate the DHCP process
send_discover_packet()

           


