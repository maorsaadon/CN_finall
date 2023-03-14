import random
import socket
import struct
import socket as s
import time
import requests

DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

# Constants:

CHUNK = 2048  # Maximum data size in packet
HEADER_SIZE = 8  # Size of packet header

DATA_PACKET = 0  # Packet type for data packets
ACK = 1  # Packet type for acknowledgement packets
SYN = 2  # Packet type for syn packet
SYN_ACK = 3  # Packet type for syn ack packet
FILE_SIZE_INFO = 4  # A special packet type for indicating the file size to be sent
FIN = 5  # Packet type for closing connection

FORMAT = '!II'  # format string for struct.pack and struct.unpack
TIMEOUT = 2  # Default timeout value for the socket

# Conventional constants for the Cubic Congestion Control algorithm
C = 0.4
beta = 0.7


def deconstruct_packet(packet):
    """
    Helper function to deconstruct a packet into its constituent parts.
    :param packet: The packet to deconstruct
    :return: A dictionary with the packet's type, sequence number, source address, and data
    """
    seq, packet_type = struct.unpack(FORMAT, packet[0][:HEADER_SIZE])
    return {'type': packet_type, 'seq': seq, 'src_address': packet[1], 'data': packet[0][HEADER_SIZE:]}


class RUDPServer:
    """
    A simple Reliable UDP (RUDP) server implementation
    """
    def __init__(self, ip, port):
        self.sock = s.socket(s.AF_INET, s.SOCK_DGRAM)  # Create a UDP socket
        self.sock.setblocking(False)  # Set socket to non-blocking mode
        self.sock.settimeout(TIMEOUT)  # Set socket timeout to the default value
        self.packets_to_send = {}  # Dictionary for holding packets to be sent
        self.sent_items = {}  # Dictionary for holding packets that have been sent but not yet acknowledged
        self.outgoing_seq = random.randint(0, (2 ** 16))  # Sequence number for outgoing packets
        self.cwnd = 1  # Initial congestion window size
        self.w_max = self.cwnd  # Maximum window size
        self.slow_start_threshold = 16  # Initial slow start threshold
        self.congestion_avoidance = False  # Flag for indicating whether we are currently in congestion avoidance phase
        self.last_window_reduction = 0  # Timestamp for the last time we reduced the congestion window
        self.file_size = 0  # Size of the file to be sent
        self.rtt = 0  # Estimated round-trip time in seconds
        self.server_address = ip, port  # Server IP address and port number
        self.target_address = None  # Client IP address and port number
        self.connected = False  # Flag for indicating whether the server is currently connected to a client
        self.requests = {}  # Dictionary for holding requests
        self.file_info_sent = False  # Flag for indicating whether the file size information has been sent

    def increment_seq(self):
        self.outgoing_seq += 1

    def bind(self):
        """
        Bind the socket to the specified address and port.
        """
        self.sock.bind(self.server_address)

    def accept_connection(self):
        while not self.connected:
            try:
                type, seq, address, _ = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                self.target_address = (address[0], 30000 + MAOR_LAST3_ID_DIG)
                if type == SYN:
                    syn_ack_packet = struct.pack(FORMAT, self.outgoing_seq, SYN_ACK)
                    self.sock.sendto(syn_ack_packet, self.target_address)
                    self.increment_seq()
                    self.connected = True
                    print(f"Connection established with client at IP address: {address[0]}")
            except socket.timeout:
                continue

    def receive_packet(self):
        type, seq, address, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
        return type, seq, address, data

    def cubic_algo(self, T):
        """
        Implementation of the Cubic Congestion Control algorithm.
        :param T: Time elapsed since last window reduction
        :return: New congestion window size
        """
        K = ((self.w_max * (1 - beta)) / C) ** (1 / 3)
        cwnd = C * ((T - K) ** 3) + self.w_max
        return cwnd

    def send_data(self):
        while self.packets_to_send:
            # CC algo:
            # slow start
            if not self.congestion_avoidance:
                if self.cwnd >= self.slow_start_threshold:
                    self.congestion_avoidance = True
                else:
                    self.cwnd *= 2

            # congestion avoidance
            else:
                now = time.time()
                time_elapsed = now - self.last_window_reduction
                # calculate new congestion window size using cubic algorithm
                new_cwnd = self.cubic_algo(time_elapsed)

                if new_cwnd >= self.cwnd:
                    self.cwnd = new_cwnd
                else:  # the new window is smaller than the old window
                    self.w_max = self.cwnd
                    self.last_window_reduction = time.time()
                    self.slow_start_threshold = max(self.cwnd / 2, 1)
                    self.cwnd = self.slow_start_threshold
                    self.congestion_avoidance = False

            # send payload
            if not self.file_info_sent:
                self.send_packet_count()

            packets = []
            first_seq_sent = min(self.packets_to_send.items())
            for seq, data in self.packets_to_send.items():
                # don't send more packets than what the congestion window allows:
                if first_seq_sent + seq < self.cwnd:
                    packets.append(data)

            time_of_sending = time.time()
            # Send all the packets at once using the socket
            self.sock.sendto(b''.join(packets), self.target_address)

            # Receive acks
            try:
                while self.packets_to_send:
                    packet_type, _, _, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                    time_of_ack = time.time()
                    if packet_type == FIN_ACK:
                        break
                    if packet_type == ACK:
                        acked_seq = int(data.decode()[5:])
                        if acked_seq in self.packets_to_send:  # if this is an acknowledgement packet for a
                            if acked_seq == first_seq_sent:
                                self.rtt = time_of_sending - time_of_ack
                                self.sock.settimeout(self.rtt / 2)
                            self.sent_items[acked_seq](self.packets_to_send.pop(acked_seq))

            except socket.timeout:
                continue

        self.close_connection()

    def construct_payload(self, data):
        seq = self.outgoing_seq
        for i in range((self.file_size + CHUNK) // CHUNK):
            data_packet = struct.pack(FORMAT, seq, DATA_PACKET)
            data_packet += data[(i * CHUNK):((i + 1) * CHUNK)]
            self.packets_to_send[seq] = data_packet
            seq += 1
        self.outgoing_seq = seq

    def send_packet_count(self):
        seq = self.outgoing_seq
        self.increment_seq()
        packet_count = len(self.packets_to_send)
        file_size_info_packet = struct.pack(FORMAT, seq, FILE_SIZE_INFO)
        file_size_info_packet += f"Number of Packets: {packet_count}".encode()
        self.sock.sendto(file_size_info_packet, self.target_address)

        # receive ack for file info
        attempts = 10
        while not self.file_info_sent and attempts > 0:
            try:
                type, _, _, data = self.receive_packet()
                acked_seq = int(data.decode()[5:])
                if type == ACK and acked_seq == seq:
                    self.file_info_sent = True
                    return
            except socket.timeout:
                attempts -= 1
                continue
        self.close_connection(force=True, comment="Could not send file info")

    def close_connection(self, force=False, comment=""):

        if not force:
            # construct the CLOSE_CONNECTION packet and send it
            seq = self.outgoing_seq
            packet = struct.pack(FORMAT, seq, FIN)
            self.sock.sendto(packet, self.target_address)
            self.increment_seq()

            # receive ack
            attempts = 10
            while attempts > 0:
                try:
                    packet_type, _, _, data = self.receive_packet()
                    if packet_type == ACK:
                        acked_seq = int(data.decode()[5:])
                        if acked_seq == seq:
                            print("Closing the socket...")
                            break
                except socket.timeout:
                    attempts -= 1

            force = not attempts

        if force:
            print(f"Something went wrong. {comment}. Forcing disconnection with client...")

        self.sock.close()
        print("Socket closed.")


# app server

IP = "127.0.0.1"
PORT = 20000 + DOVI_LAST3_ID_DIG


def downloadmanager():

    rudp_s = RUDPServer(IP, PORT)
    rudp_s.bind()
    print("Ready to serve...")

    rudp_s.accept_connection()

    while True:
        try:
            t, seq, address, data = rudp_s.receive_packet()
            print("Request packet received...")

            # string manipulation to extract host name anf file name
            print("Extracting URL...")
            request_string = data.decode()
            request_lines = request_string.split("\r\n")
            file_name = request_lines[0][5: -9]
            host_name = request_lines[1][6:]

            url = f"http://{host_name}/{file_name}"
            print(f"URL for http GET request: {url}")

            # http get request
            print("Sending HTTP GET request...")
            response = requests.get(url)

            print(f"Getting file: {file_name} from: {host_name}...")
            print("Retreiving file data...")
            data = response.content

            rudp_s.file_size = len(data)

            print("Preparing file for download...")
            rudp_s.construct_payload(data)

            print("Downloading file...")
            rudp_s.send_data()

            print("Download completed successfully!")

            return

        except socket.timeout:
            pass


if __name__ == '__main__':
    downloadmanager()
