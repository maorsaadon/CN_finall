import os
import random
import socket
import struct
import socket as s
import time
import requests

DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

# Define constants
DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

CHUNK = 2048  # Maximum data size in packet
HEADER_SIZE = 8  # Size of packet header
DATA_PACKET = 0  # Packet type for data packets
ACK_PACKET = 1  # Packet type for acknowledgement packets
SYN_PACKET = 2  # Packet type for syn packet
SYN_ACK_PACKET = 3  # Packet type for syn ack packet
FILE_SIZE_INFO = 4  # A special packet type for indicating the file size to be sent
CLOSE_CONNECTION = 5  # Packet type for closing connection
REQUEST_PACKET = 7
REQUEST_ACK = 8
FORMAT = '!II'  # format string for struct.pack and struct.unpack
TIMEOUT = 2  # Default timeout value for the socket
ATTEMPT_LIMIT = 10  # Maximum number of times to attempt to send a packet

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
    A simple Reliable UDP (RUDP) server implementation using Python's socket library.
    """

    def __init__(self, ip, port):
        self.sock = s.socket(s.AF_INET, s.SOCK_DGRAM)  # Create a UDP socket
        self.sock.setblocking(False)  # Set socket to non-blocking mode
        self.sock.settimeout(TIMEOUT)  # Set socket timeout to the default value
        self.packets_to_send = {}  # Dictionary for holding packets to be sent
        self.sent_items = {}  # Dictionary for holding packets that have been sent but not yet acknowledged
        self.first_seq = self.outgoing_seq = random.randint(0, (2 ** 16))  # Sequence number for outgoing packets
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

    def bind(self):
        """
        Bind the socket to the specified address and port.
        """
        self.sock.bind(self.server_address)

    def accept_connection(self):
        attempts = 10
        while not self.connected and attempts > 0:
            try:
                type, seq, address, _ = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                if type == SYN_PACKET:
                    syn_ack_packet = struct.pack(FORMAT, self.outgoing_seq, SYN_ACK_PACKET)
                    self.outgoing_seq += 1
                    syn_ack_packet += f"ACK: {seq}".encode()
                    self.sock.sendto(syn_ack_packet, address)
                    self.connected = True
                    self.target_address = address
            except socket.timeout:
                continue
        if attempts == 0:
            print("Something went wrong! could not establish connection with client...")
            self.close_connection(force=True)

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

    def send_data(self, address):
        while len(self.packets_to_send) > 0:
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
            first_seq_sent = min(self.packets_to_send)
            for seq, data in self.packets_to_send.items():
                print(struct.unpack(FORMAT, data[:HEADER_SIZE]))
                packets.append(data)
                self.sent_items[seq] = data
            # Send all the packets at once using the socket
            time_of_sending = time.time()
            self.sock.sendto(b''.join(packets), address)

            # receive acks
            try:
                while len(self.packets_to_send) > 0:
                    type, _, _, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                    time_of_ack = time.time()

                    if type == ACK_PACKET:
                        acked_seq = int(data.decode()[5:])
                        if acked_seq in self.sent_items:  # if this is an acknowledgement packet for a
                            if acked_seq == first_seq_sent:
                                self.rtt = time_of_sending - time_of_ack
                                self.sock.settimeout(2)
                            self.sent_items.pop(acked_seq)
                            self.packets_to_send.pop(acked_seq)
            except socket.timeout:
                pass

        # loop breaks if and only if all packets were sent and acked, and only then connection is closed:
        self.close_connection()
        return

    def construct_payload(self, data):
        seq = self.outgoing_seq
        for i in range(self.file_size + CHUNK // CHUNK):
            data_packet = struct.pack(FORMAT, seq, DATA_PACKET)
            data_packet += data[(i * CHUNK):min(len(data), (i + 1) * CHUNK)]
            self.packets_to_send[seq] = data_packet
            seq += 1
        self.outgoing_seq = seq

    def send_packet_count(self):
        seq_to_send = min(0, min(self.packets_to_send) - 1)
        packet_count = len(self.packets_to_send)
        file_size_info_packet = struct.pack(FORMAT, seq_to_send, FILE_SIZE_INFO)
        file_size_info_packet += f"Number of Packets: {packet_count}".encode()
        self.sock.sendto(file_size_info_packet, self.target_address)

        # receive ack for file info
        attempts = 10
        while not self.file_info_sent and attempts > 0:
            try:
                type, _, _, data = self.receive_packet()
                acked_seq = int(data.decode()[5:])
                if type == ACK_PACKET and acked_seq == seq_to_send:
                    self.file_info_sent = True
                    return
            except socket.timeout:
                attempts -= 1
                continue
        print("Something went wrong! could not send file info")
        self.close_connection(force=True)

    def close_connection(self, force=False):
        if force:
            print("Something went wrong. forcing disconnection with client...")

        while not force:
            # construct the CLOSE_CONNECTION packet and send it
            packet = struct.pack(FORMAT, self.outgoing_seq, CLOSE_CONNECTION)
            self.sock.sendto(packet, self.target_address)

            attempts = 10
            while attempts > 0:
                try:
                    type, _, _, data = self.receive_packet()
                    if type == ACK_PACKET:
                        ack_seq = data.decode()[5:]
                        if ack_seq == self.outgoing_seq:
                            force = True
                            break
                except socket.timeout:
                    attempts -= 1
        self.sock.close()
        return


# app server

IP = "127.0.0.1"
PORT = 20000 + DOVI_LAST3_ID_DIG


def downloadmanager():
    rudp_s = RUDPServer(IP, PORT)
    rudp_s.bind()
    print("Ready to serve...")
    rudp_s.accept_connection()

    time_to_wait = 30  # in seconds...
    elapsed_time = 0
    current_time = time.time()
    time_stamp = current_time
    request = ''
    while time_to_wait > 0:
        try:
            t, seq, address, data = rudp_s.receive_packet()

            print("Request received")
            # string manipulation to extract host name anf file name
            print("Extracting URL...")
            request_string = data.decode()
            request_lines = request_string.split("\r\n")
            file_name = request_lines[0][5: -9]
            host = request_lines[1][6:]

            url = f"http://{host}/{file_name}"
            print(f"URL for http GET request: {url}")

            # http get request
            print(f"Getting file: {file_name} from: {host}...")
            response = requests.get(url)
            print("Retreiving file data...")
            data = response.content
            rudp_s.file_size = len(data)
            print("Preparing file for download...")
            print("Downloading file...")
            rudp_s.construct_payload(data)
            rudp_s.send_data(address)
            print("Download completed successfully!")

        except socket.timeout:
            pass
        time_stamp = time.time()
        elapsed_time = current_time - time_stamp
        current_time = time_stamp
        time_to_wait -= elapsed_time
    print("No requests submitted for more than a minute! closing connection!")
    rudp_s.close_connection(force=True)
    return


if __name__ == '__main__':
    downloadmanager()
