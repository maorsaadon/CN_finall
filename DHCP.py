from scapy.all import *
import random

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


class DhcpHandler:
    def __init__(self):
        self.ip_pool = ['192.168.0.%d' % i for i in range(100, 200)]

    def handle(self, pkt):
        if pkt[DHCP] and pkt[DHCP].options[0][1] == 1: # DHCP Discover
            # Extract the client's MAC address from the request
            mac_address = pkt[Ether].src.replace(':', '')

            # Assign the next available IP address to the client
            ip_address = random.choice(self.ip_pool)

            # Construct the DHCP offer
            offer = Ether(src=get_if_hwaddr(conf.iface), dst=pkt[Ether].src) / \
                    IP(src=get_if_addr(conf.iface), dst='255.255.255.255') / \
                    UDP(sport=67, dport=68) / \
                    BOOTP(op=2, yiaddr=ip_address, siaddr=get_if_addr(conf.iface), chaddr=pkt[Ether].src) / \
                    DHCP(options=[('message-type', 'offer'),
                                   ('server_id', get_if_addr(conf.iface)),
                                   ('lease_time', 86400),
                                   ('subnet_mask', '255.255.255.0'),
                                   ('router', get_if_addr(conf.iface)),
                                   'end'])

            # Send the DHCP offer to the client
            sendp(offer, iface=conf.iface)

        elif pkt[DHCP] and pkt[DHCP].options[0][1] == 3: # DHCP Request
            # Extract the client's MAC address and requested IP address from the request
            mac_address = pkt[Ether].src.replace(':', '')
            requested_ip = pkt[BOOTP].yiaddr

            # Assign the requested IP address to the client
            ip_address = requested_ip

            # Construct the DHCP ACK
            ack = Ether(src=get_if_hwaddr(conf.iface), dst=pkt[Ether].src) / \
                  IP(src=get_if_addr(conf.iface), dst='255.255.255.255') / \
                  UDP(sport=67, dport=68) / \
                  BOOTP(op=2, yiaddr=ip_address, siaddr=get_if_addr(conf.iface), chaddr=pkt[Ether].src) / \
                  DHCP(options=[('message-type', 'ack'),
                                 ('server_id', get_if_addr(conf.iface)),
                                 ('lease_time', 86400),
                                 ('subnet_mask', '255.255.255.0'),
                                 ('router', get_if_addr(conf.iface)),
                                 'end'])

            # Send the DHCP ACK to the client
            sendp(ack, iface=conf.iface)

if __name__ == '__main__':
    handler = DhcpHandler()
    sniff(filter='udp and (port 67 or port 68)', prn=handler.handle)
