import os
import random
import socket
import struct
import socket as s
import time
import requests

# Constants
CHUNK = 2048  # Maximum data size in packet
HEADER_SIZE = 8  # Size of packet header
DATA_PACKET = 0  # Packet type for data packets
ACK_PACKET = 1  # Packet type for acknowledgement packets
SYN_PACKET = 2  # Packet type for syn packet
SYN_ACK_PACKET = 3  # Packet type for syn ack packet
FILE_SIZE_INFO = 4  # a special packet type for indicating the file size to be sent.
CLOSE_CONNECTION = 5  # Packet type for closing connection
CLOSE_CONNECTION_ACK = 6  # Packet type for acknowledging connection closure #TODO ack
REQUEST_PACKET = 7
REQUEST_ACK = 8
FORMAT = '!II'  # format string for struct.pack and struct.unpack
TIMEOUT = 2
ATTEMPT_LIMIT = 10

# conventional constants for cubic CC algo:
C = 0.4
beta = 0.7


def deconstruct_packet(packet):
    seq, packet_type = struct.unpack(FORMAT, packet[0][:HEADER_SIZE])
    return {'type': packet_type, 'seq': seq, 'src_address': packet[1], 'data': packet[0][HEADER_SIZE:]}


class RUDPServer:
    def __init__(self, ip, port):
        self.sock = s.socket(s.AF_INET, s.SOCK_DGRAM)  # Create a UDP socket
        self.sock.setblocking(False)  # Set socket to non-blocking mode
        self.sock.settimeout(TIMEOUT)  # Set socket timeout to 1 second
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
        self.server_address = ip, port
        self.target_address = None
        self.connected = False
        self.requests = {}

    # server functions

    def bind(self):
        """
        Bind the socket to the specified address and port.
        """
        self.sock.bind(self.server_address)

    def accept_connection(self):
        while not self.connected:
            try:
                type, seq, address, _ = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                if type == SYN_PACKET:
                    syn_ack_packet = struct.pack(FORMAT, self.outgoing_seq, SYN_ACK_PACKET)
                    self.sock.sendto(syn_ack_packet, address)
                    self.connected = True
                    self.target_address = address
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

    def send_data(self, address):
        while True:
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
            packets = []
            first_seq_sent = self.outgoing_seq
            for seq, data in self.packets_to_send.items():
                packets.append(data)
                self.sent_items[seq] = self.packets_to_send[seq]
                self.outgoing_seq += 1

            # Send all the packets at once using the socket
            time_of_sending = time.time()
            self.sock.sendto(b''.join(packets), address)
            self.outgoing_seq = seq

            # receive acks
            try:
                while True:
                    type, seq, _, _ = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                    time_of_ack = time.time()

                    if type == ACK_PACKET and seq in self.sent_items:  # if this is an acknowledgement packet for a
                        # sent packet
                        if seq == first_seq_sent:
                            self.rtt = time_of_sending - time_of_ack
                            self.sock.settimeout(2)
                        self.sent_items.pop(seq)
                        self.packets_to_send.pop(seq)
            except socket.timeout:
                if len(self.packets_to_send) == len(self.sent_items) == 0:  # all packets were sent and acked
                    break

        # loop breaks if and only if all packets were sent and acked, and only then connection is closed:
        self.close_connection()

    def construct_payload(self, data):
        # first_seq = self.outgoing_seq
        # seq = first_seq #+ 1
        seq = self.outgoing_seq
        for i in range((self.file_size // CHUNK) + 1):
            data_packet = struct.pack(FORMAT, seq, DATA_PACKET)
            data_packet += data[(i * CHUNK):((i + 1) * CHUNK)]
            self.packets_to_send[seq] = data_packet
            seq += 1

        # packet_count_info = struct.pack(FORMAT, first_seq, FILE_SIZE_INFO)
        # packet_count_info += bytes(len(self.packets_to_send))
        # self.packets_to_send[first_seq] = packet_count_info

    def close_connection(self):

        # This function is responsible for closing the connection after all data has been sent and acknowledged. It
        # sends a CLOSE_CONNECTION packet to the other end and waits for a CLOSE_CONNECTION_ACK packet before closing
        # the socket.

        # while True:
        #     # construct the CLOSE_CONNECTION packet and send it
        #     packet = struct.pack(FORMAT, self.outgoing_seq, CLOSE_CONNECTION)
        #     packet += b'Closing connection'
        #     self.sock.sendto(packet, self.target_address)
        self.sock.close()
            # try:
            #     # wait for a response packet from the other end
            #     type, seq, _, _ = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
            #
            #     if type == CLOSE_CONNECTION_ACK:
            #         # if a CLOSE_CONNECTION_ACK packet is received, close the socket and exit the loop
            #         self.sock.close()
            #         print("Connection closed.")
            #         break
            # except socket.timeout:
            #     # if an error occurs while waiting for the response packet, continue waiting
            #     continue


# app server

IP = "127.0.0.1"
PORT = 30000


def downloadmanager():
    rudp_s = RUDPServer(IP, PORT)
    rudp_s.bind()
    print("Ready to serve...")
    rudp_s.accept_connection()

    time_to_wait = 60
    elapsed_time = 0
    current_time = time.time()
    time_stamp = current_time
    request = ''
    while time_to_wait > 0:
        try:
            t, seq, address, data = rudp_s.receive_packet()

            print("Request received")
            # string manipulation to extract host name anf file name
            request_string = data.decode()
            request_lines = request_string.split("\r\n")
            file_name = request_lines[0][5: -9]
            host = request_lines[1][6:]
            url = f"http://{host}/{file_name}"

            # http get request
            response = requests.get(url)
            data = response.content
            rudp_s.file_size = len(data)
            rudp_s.construct_payload(data)
            rudp_s.send_data(address)
            print("FLAG")
            print("file sent.")

        except socket.timeout:
            pass
        time_stamp = time.time()
        elapsed_time = current_time - time_stamp
        current_time = time_stamp
        time_to_wait -= elapsed_time
    print("No requests submitted for more than a minute! closing connection!")
    rudp_s.sock.close()
    return


if __name__ == '__main__':
    downloadmanager()
