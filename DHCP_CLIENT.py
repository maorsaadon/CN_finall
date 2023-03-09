from scapy.all import *

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


mac_address = get_if_hwaddr(conf.iface)
ip_address = None
 

def handle_offer_packet(packet):
    print("DHCP offer received")
    send_request_packet(packet)

def handle_ack_packet(packet):
    print("DHCP ack received")

def send_discover_packet():
    discover = Ether(src=mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                IP(src='0.0.0.0', dst='255.255.255.255') / \
                UDP(sport=68, dport=67) / \
                BOOTP(op=1, chaddr=mac_address) / \
                DHCP(options=[('message-type', 'discover'), 'end', 'pad'])

    ("sending DHCP Discover")
    sendp(discover)

    sniff(prn=handle_offer_packet, filter='(port 67 or port 68)', count=1)

def send_request_packet(offer):
    ip_address = offer[BOOTP].yiaddr
    request = Ether(src=mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                IP(src='0.0.0.0', dst='255.255.255.255') / \
                UDP(sport=68, dport=67) / \
                BOOTP(op=1, chaddr=mac_address, yiaddr=ip_address, siaddr=get_if_addr(conf.iface)) / \
                DHCP(options=[('message-type', 'request'),
                            ('requested_addr', ip_address), 
                            ('server_id', offer[DHCP].options[1][1]), 'end', 'pad'])
    time.sleep(1)
    ("sending DHCP Request")
    sendp(request)

    sniff(prn=handle_ack_packet, filter='(port 67 or port 68)', count=1)


send_discover_packet()
