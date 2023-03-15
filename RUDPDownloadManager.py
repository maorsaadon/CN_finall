import errno
import random
import socket
import struct
import socket as s
import time
import requests

# last 3 digits of the id for DOVI and MAOR
DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

# Constants:
# Maximum data size in packet
CHUNK = 1024
# Size of packet header
HEADER_SIZE = 8

# Packet types
DATA_PACKET = 0  # Packet type for data packets
ACK = 1  # Packet type for acknowledgement packets
SYN = 2  # Packet type for syn packet
SYN_ACK = 3  # Packet type for syn ack packet
FILE_SIZE_INFO = 4  # A special packet type for indicating the file size to be sent
FIN = 5  # Packet type for closing connection
FIN_ACK = 6


# struct.pack format string
FORMAT = '!II'

# Default timeout value for the socket
TIMEOUT = 2

# Conventional constants for the Cubic Congestion Control algorithm
C = 0.4
beta = 0.7


def deconstruct_packet(packet):
    """
    Helper function to deconstruct a packet into its constituent parts.
    :param packet: The packet to deconstruct
    :return: A dictionary with the packet's type, sequence number, source address, and data
    """
    # Unpacks the sequence number and packet type from the packet's header
    seq, packet_type = struct.unpack(FORMAT, packet[0][:HEADER_SIZE])
    # Returns a dictionary containing the packet's type, sequence number, source address, and data
    return {'type': packet_type, 'seq': seq, 'src_address': packet[1], 'data': packet[0][HEADER_SIZE:]}


class RUDPServer:
    """
    A simple Reliable UDP (RUDP) server implementation
    """
    def __init__(self, ip, port):
        # Creates a UDP socket
        self.sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
        # Sets socket to non-blocking mode
        self.sock.setblocking(False)
        # Sets socket timeout to the default value
        self.sock.settimeout(TIMEOUT)
        # Dictionary for holding packets to be sent
        self.packets_to_send = {}
        # Dictionary for holding packets that have been sent but not yet acknowledged
        self.sent_items = {}
        # Sequence number for outgoing packets
        self.outgoing_seq = random.randint(0, (2 ** 16))
        # Initial congestion window size
        self.cwnd = 1
        # Maximum window size
        self.w_max = self.cwnd
        # Initial slow start threshold
        self.slow_start_threshold = 16
        # Flag for indicating whether we are currently in congestion avoidance phase
        self.congestion_avoidance = False
        # Timestamp for the last time we reduced the congestion window
        self.last_window_reduction = 0
        # Size of the file to be sent
        self.file_size = 0
        # Estimated round-trip time in seconds
        self.rtt = 0
        # Server IP address and port number
        self.server_address = ip, port
        # Client IP address and port number
        self.target_address = None
        # Flag for indicating whether the server is currently connected to a client
        self.connected = False
        # Dictionary for holding requests
        self.requests = {}
        # Flag for indicating whether the file size information has been sent
        self.file_info_sent = False
        self.increment_seq = lambda: setattr(self, "outgoing_seq", self.outgoing_seq + 1)

    def confirm_sent(self, bytes, packet):
        return bytes == len(packet)

    def bind(self):
        """
        Bind the socket to the specified address and port.
        """
        # Bind the socket to the server address specified in self.server_address
        self.sock.bind(self.server_address)

    def accept_connection(self):
        # Loop until a connection is established with a client
        while not self.connected:
            try:
                # Receive a packet and extract its fields
                type, seq, address, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
                self.target_address = address
                # If the packet is a SYN packet, send a SYN-ACK packet back to the client
                if type == SYN:
                    syn_ack_packet = struct.pack(FORMAT, self.outgoing_seq, SYN_ACK)
                    bytes = self.sock.sendto(syn_ack_packet, self.target_address)
                    self.increment_seq()
                    if self.confirm_sent(bytes, syn_ack_packet):
                        self.connected = True
                        print(f"Connection established with client at IP address: {address[0]}")
                    else:
                        print(f"Error sending message: {errno}")

                    # Print a message to indicate that the connection was established
            except socket.timeout:
                # If a timeout occurs while waiting for a packet, continue the loop and try again
                continue

    def receive_packet(self):
        # Receive a packet and extract its fields, then return them
        type, seq, address, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()
        return type, seq, address, data

    def cubic_algo(self, T):
        """
        Implementation of the Cubic Congestion Control algorithm.
        :param T: Time elapsed since last window reduction
        :return: New congestion window size
        """
        # Calculate the scaling factor K based on the current window size and elapsed time since the last window reduction
        K = ((self.w_max * (1 - beta)) / C) ** (1 / 3)
        # Calculate the new congestion window size using the cubic function
        cwnd = C * ((T - K) ** 3) + self.w_max
        return cwnd

    def send_data(self):
        all_packets_sent = False
        while self.packets_to_send and not all_packets_sent:
            # Congestion Control algorithm:

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
            # If file info has not been sent, send it first
            if not self.file_info_sent:
                self.send_packet_count()

            packets = []
            first_seq_sent = min(self.packets_to_send)
            for seq, data in self.packets_to_send.items():
                # don't send more packets than what the congestion window allows:
                if seq - first_seq_sent <= self.cwnd:
                    packets.append(data)

            time_of_sending = time.time()
            # Send all the packets at once using the socket
            if len(b''.join(packets)) > 0:
                sent = self.sock.sendto(b''.join(packets), self.target_address)
                if sent == len(b''.join(packets)):
                    print(f"Packet sent successfully.\n")
                else:
                    print(f"Error sending message: {errno}")

            # Receive acks
            try:
                while self.packets_to_send:

                    packet_type, _, _, data = deconstruct_packet(self.sock.recvfrom(CHUNK)).values()

                    if packet_type == FIN:
                        all_packets_sent = True
                        print("All packets sent successfully to client.\n")
                        break

                    if packet_type == ACK:

                        time_of_ack = time.time()

                        acked_seq = int(data.decode()[5:])
                        if acked_seq in self.packets_to_send:  # if this is an acknowledgement packet for a
                            if acked_seq == first_seq_sent:
                                # calculate RTT
                                self.rtt = time_of_sending - time_of_ack
                                self.sock.settimeout(max(10, int(self.rtt // 2)))

                            # remove packet from packets_to_send and save in sent_items
                            self.sent_items[acked_seq] = self.packets_to_send.pop(acked_seq)

            except socket.timeout:
                continue

        # close the connection
        self.close_connection()

    def construct_payload(self, data):
        # Calculate the number of chunks needed to send the entire file
        seq = self.outgoing_seq
        for i in range((self.file_size + CHUNK) // CHUNK):
            # Pack the sequence number and packet type into a data packet
            data_packet = struct.pack(FORMAT, seq, DATA_PACKET)
            # Add a chunk of data to the packet
            data_packet += data[(i * CHUNK):((i + 1) * CHUNK)]
            # Store the packet in a dictionary, indexed by its sequence number
            self.packets_to_send[seq] = data_packet
            seq += 1
        # Update the outgoing sequence number to the next available number
        self.outgoing_seq = seq

    def send_packet_count(self):
        seq = self.outgoing_seq
        # Increment the outgoing sequence number to use for the file size info packet
        self.increment_seq()
        # Pack the number of packets to send into a file size info packet
        packet_count = len(self.packets_to_send)
        file_size_info_packet = struct.pack(FORMAT, seq, FILE_SIZE_INFO)
        file_size_info_packet += f"Number of Packets: {packet_count}".encode()
        # Send the file size info packet to the target address and wait for a confirmation
        bytes = self.sock.sendto(file_size_info_packet, self.target_address)
        if self.confirm_sent(bytes, file_size_info_packet):
            print("File info sent successfully.\n")
            # Increment the sequence number for the outgoing packets and set the connection status to connected
        else:
            print(f"Error sending message: {errno}")

        # Wait for an acknowledgement that the file info packet was received
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
        # If the file info packet was not acknowledged, close the connection with an error message
        self.close_connection(force=True, comment="Could not send file info")

    def close_connection(self, force=False, comment=""):
        # If the connection is not being forced closed...
        if not force:
            # Construct a FIN-ACK packet and send it
            seq = self.outgoing_seq
            packet = struct.pack(FORMAT, seq, FIN_ACK)
            self.sock.sendto(packet, self.target_address)
            # Increment the outgoing sequence number
            self.increment_seq()

            # Wait for an acknowledgement of the FIN-ACK packet
            attempts = 10
            while attempts > 0:
                try:
                    packet_type, _, _, data = self.receive_packet()
                    if packet_type == ACK:
                        acked_seq = int(data.decode()[5:])
                        if acked_seq == seq:
                            print("Closing the socket...\n")
                            break
                except socket.timeout:
                    attempts -= 1

            force = not attempts

        # If the connection is being forced closed or the FIN-ACK packet was not acknowledged...
        if force:
            # Print an error message with a comment about the reason for the forced close
            print(f"Something went wrong. {comment}. Forcing disconnection with client...\n")

        # Close the socket and print a message
        self.sock.close()
        print("Socket closed.\n")


# app server
#Define IP address and port number
IP = "127.0.0.1"
PORT = 20000 + DOVI_LAST3_ID_DIG


def download_manager():

    rudp_s = RUDPServer(IP, PORT)
    rudp_s.bind()
    print("Ready to serve...\n")

    rudp_s.accept_connection()

    # Create a RUDPServer object with the defined IP and port number
    rudp_s = RUDPServer(IP, PORT)
    rudp_s.bind()
    print("Ready to serve...\n")

    # Accept incoming connection requests
    rudp_s.accept_connection()

    while True:
        try:
            # Receive a packet from the client
            t, seq, address, data = rudp_s.receive_packet()
            print("Request packet received...\n")

            # Extract the file name and host name from the request data
            print("Extracting URL...")
            request_string = data.decode()
            request_lines = request_string.split("\r\n")
            file_name = request_lines[0][5: -9]
            host_name = request_lines[1][6:]

            # Construct the URL for the HTTP GET request
            url = f"http://{host_name}/{file_name}"
            print(f"URL for http GET request: {url}.\n")

            # Send an HTTP GET request to the server
            print("Sending HTTP GET request...\n")
            response = requests.get(url)

            # Retry up to 10 times if the GET request fails
            request_received = False
            for attempt in range(10):
                if response.status_code >= 200 and response.status_code < 300:
                    print("GET request successful.\n")
                    request_received = True
                    break

            # If the GET request still fails, print an error message and return
            if not request_received:
                print(f"GET request failed with status code {response.status_code}.\n")
                return

            # Retrieve the file data from the response
            print(f"Getting file: {file_name} from: {host_name}...\n")
            print("Retreiving file data...\n")
            data = response.content

            # Set the file size in the RUDPServer object and construct the payload
            rudp_s.file_size = len(data)
            print("Preparing file for download...\n")
            rudp_s.construct_payload(data)

            # Send the data packets to the client using RUDP
            print("Downloading file...\n")
            rudp_s.send_data()

            # Print a success message and return
            print("Download completed successfully!\n")
            return

        # Ignore socket.timeout exceptions and continue
        except socket.timeout:
            pass

if __name__ == '__main__':
    download_manager()
