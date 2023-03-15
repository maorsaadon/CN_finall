import socket as s
import requests
import threading

DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421


class TCPServer:
        """
        A simple TCP server implementation
        """

        def __init__(self, ip, port):
            # Creates a TCP socket
            self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)
            self.address = ip, port

        def bind(self):
            self.sock.bind(self.address)

        def get_request(self):




IP = '127.0.0.1'
PORT = 20000 + DOVI_LAST3_ID_DIG
CHUNK = 1024

def get_request(conn, addr):

    print(f"New connection from {addr}")
    try:
        # Receive data from the client
        request = conn.recv(CHUNK)
        if not request:
            return
        # Decode the received request
        request_str = request.decode('utf-8')
        # Extract the requested URL from the HTTP GET request
        url_start = request_str.find('GET ') + 4
        url_end = request_str.find(' HTTP/1.1')
        if url_start == -1 or url_end == -1:
            raise ValueError("Invalid HTTP request")
        url = request_str[url_start:url_end]
        # Validate the requested URL
        if not url.startswith('http://') and not url.startswith('https://'):
            raise ValueError("Invalid URL scheme")
        # Download the requested file from the URL
        file = urllib.request.urlopen(url)
        # Send the HTTP response headers to the client
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        # Send the file content to the client
        while True:
            data = file.read(BUFFER_SIZE)
            if not data:
                break
            conn.sendall(data)
    except ValueError as e:
        # Send an error message to the client
        conn.sendall(f"HTTP/1.1 400 Bad Request\r\n\r\n{str(e)}".encode('utf-8'))
    except urllib.error.URLError as e:
        # Send an error message to the client
        conn.sendall(f"HTTP/1.1 404 Not Found\r\n\r\n{str(e)}".encode('utf-8'))
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        # Close the connection
        conn.close()
        print(f"Connection from {addr} closed")

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the specified host and port
server_socket.bind((HOST, PORT))
# Listen for incoming connections
server_socket.listen()
print(f"Server listening on {HOST}:{PORT}")

while True:
    # Accept incoming connections
    conn, addr = server_socket.accept()
    # Handle each request in a separate thread
    thread = threading.Thread(target=handle_request, args=(conn, addr))
    thread.start()