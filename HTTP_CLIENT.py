import socket
import struct
import os

HOST = 'localhost'
PORT = 8000
CHUNK_SIZE = 1024

def main():
    # send GET request to server
    request = b'GET /file.txt HTTP/1.1\r\nHost: localhost\r\n\r\n'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(request)
        # receive response headers
        response = b''
        while b'\r\n\r\n' not in response:
            data = s.recv(CHUNK_SIZE)
            if not data:
                raise Exception('Connection closed unexpectedly')
            response += data
        # parse content length from response headers
        content_length = int(response.split(b'Content-Length: ')[1].split(b'\r\n')[0])
        # receive file contents in chunks using RUDP protocol
        received_content = bytearray(content_length)
        offset = 0
        while offset < content_length:
            # receive RUDP message with metadata and data
            message = receive_rudp_message(s)
            chunk_offset, chunk_size = struct.unpack('!II', message[:8])
            chunk_data = message[8:]
            # write chunk data to buffer
            received_content[chunk_offset:chunk_offset+chunk_size] = chunk_data
            offset += chunk_size
        # save file to disk
        with open('file.txt', 'wb') as f:
            f.write(received_content)
        print('File downloaded successfully')

def receive_rudp_message(conn):
    # receive message length and message data as separate messages
    message_length_data = b''
    while len(message_length_data) < 4:
        data = conn.recv(4 - len(message_length_data))
        if not data:
            raise Exception('Connection closed unexpectedly')
        message_length_data += data
    message_length = struct.unpack('!I', message_length_data)[0]
    message_data = b''
    while len(message_data) < message_length:
        data = conn.recv(message_length - len(message_data))
        if not data:
            raise Exception('Connection closed unexpectedly')
        message_data += data
    return message_data

if __name__ == '__main__':
    main()
