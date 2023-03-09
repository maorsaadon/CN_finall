from scapy.all import *

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


class DhcpHandler:
    def __init__(self):
        self.ip_pool = ['192.168.0.%d' % i for i in range(100, 200)]
        self.ip_assignments = {}

    def get_next_available_ip(self):
        for ip_address in self.ip_pool:
            if str(ip_address) not in self.ip_assignments:
                return str(ip_address)
        return None

    def handle(self, packet):
        if packet[DHCP] and packet[DHCP].options[0][1] == 1: # DHCP Discover
            print("DHCP Discover received")
            # Extract the client's MAC address from the request
            mac_address = packet[Ether].src.replace(':', '')

            # Assign the next available IP address to the client
            ip_address = self.get_next_available_ip()
            # print(ip_address)
            if not ip_address:
                return  # No more IP addresses available
            
            # Add the IP address assignment to the dictionary
            self.ip_assignments[ip_address] = mac_address

            # Construct the DHCP offer
            offer =Ether(src=get_if_hwaddr(conf.iface), dst=packet[Ether].src) / \
                    IP(src=get_if_addr(conf.iface), dst='255.255.255.255') / \
                    UDP(sport=67, dport=68) / \
                    BOOTP(op=2, yiaddr=ip_address, siaddr=get_if_addr(conf.iface), chaddr=packet[Ether].src) / \
                    DHCP(options=[('message-type', 'offer'),
                                   ('server_id', get_if_addr(conf.iface)),
                                   ('lease_time', 1200),
                                   ('subnet_mask', '255.255.255.0'),
                                   ('router', get_if_addr(conf.iface)),
                                   'end', 'pad'])

            # Send the DHCP offer to the client
            time.sleep(2)
            print("sending DHCP offer")
            sendp(offer, iface=conf.iface)

        elif packet[DHCP] and packet[DHCP].options[0][1] == 3: # DHCP Request
            print("DHCP Request received")
            # Extract the client's MAC address and requested IP address from the request
            mac_address = packet[Ether].src.replace(':', '')
            requested_ip = packet[BOOTP].yiaddr

            # Assign the requested IP address to the client
            ip_address = requested_ip

            # Construct the DHCP ACK
            ack =Ether(src=get_if_hwaddr(conf.iface), dst=packet[Ether].src) / \
                  IP(src=get_if_addr(conf.iface), dst='255.255.255.255') / \
                  UDP(sport=67, dport=68) / \
                  BOOTP(op=5, yiaddr=ip_address, siaddr=get_if_addr(conf.iface), chaddr=packet[Ether].src) / \
                  DHCP(options=[('message-type', 'ack'),
                                 ('server_id', get_if_addr(conf.iface)),
                                 ('lease_time', 1200),
                                 ('subnet_mask', '255.255.255.0'),
                                 ('router', get_if_addr(conf.iface)),
                                 'end', 'pad'])

            # Send the DHCP ACK to the client
            time.sleep(2)
            print("sending DHCP ack")
            sendp(ack, iface=conf.iface)

if __name__ == '__main__':
    handler = DhcpHandler()
    #capture and process network traffic that matches a specified filter.
    sniff(filter='udp and (port 67 or port 68)', prn=handler.handle)