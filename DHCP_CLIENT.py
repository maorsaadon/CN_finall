from scapy.all import *
import random

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


class DhcpClient:
    def __init__(self):
        self.mac_address = get_if_hwaddr(conf.iface)
        self.ip_address = None

    def send_discover_packet(self):
        discover = Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                   IP(src='0.0.0.0', dst='255.255.255.255') / \
                   UDP(sport=68, dport=67) / \
                   BOOTP(op=1, chaddr=self.mac_address) / \
                   DHCP(options=[('message-type', 'discover'), 'end'])

        offer = srp1(discover, iface=conf.iface, timeout=10)
        if offer and offer[DHCP] and offer[DHCP].options[0][1] == 2:  # DHCP Offer
            self.ip_address = offer[BOOTP].yiaddr

    def send_request_packet(self):
        request = Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') / \
                  IP(src='0.0.0.0', dst='255.255.255.255') / \
                  UDP(sport=68, dport=67) / \
                  BOOTP(op=1, chaddr=self.mac_address) / \
                  DHCP(options=[('message-type', 'request'),
                                ('requested_addr', self.ip_address),
                                ('server_id', self.offer[DHCP].options[1][1]), 'end'])

        ack = srp1(request, iface=conf.iface, timeout=10)
        if ack and ack[DHCP] and ack[DHCP].options[0][1] == 5:  # DHCP Ack
            print(f"DHCP IP address assignment successful. Assigned IP: {self.ip_address}")
        else:
            print("DHCP IP address assignment failed.")

    def run(self):
        self.send_discover_packet()
        if self.ip_address:
            self.send_request_packet()


if __name__ == '__main__':
    client = DhcpClient()
    client.run()
