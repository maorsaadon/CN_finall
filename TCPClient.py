import socket as s

DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

class TCPClient:
    """
    A simple TCP client implementation
    """

    def __init__(self):
        # Creates a TCP socket
        self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)

    def socket(self):
        return self.sock

    def connect(self, server_ip, server_port):
        try:
            # Connect to the server
            self.sock.connect((server_ip, server_port))
            print(f"Connected to server {server_ip}:{server_port}\n")
        except ConnectionRefusedError as e:
            print(f"Error connecting to server: {e}")
            return False
        return True


BUFFER = 4096
SERVER_IP = '127.0.0.1'
SERVER_PORT = 20000 + DOVI_LAST3_ID_DIG


def client_request(url, file_name):
    tcp_c = TCPClient()

    # Connect to the server
    connected = tcp_c.connect(SERVER_IP, SERVER_PORT)
    if not connected:
        return

    # Construct the HTTP request
    http_request = f"GET /{file_name} HTTP/1.1\r\nHost: {url}\r\n\r\n".encode()

    # Send the HTTP request to the server
    try:
        tcp_c.socket().send(http_request)
        print("Request sent.\n")
    except ConnectionResetError as e:
        print(f"Error sending request to server: {e}")
        return

    # Receive the HTTP response from the server
    response = b''
    while True:
        try:
            chunk = tcp_c.socket().recv(BUFFER)
        except ConnectionResetError as e:
            print(f"Error receiving response from server: {e}")
            return
        if not chunk:
            break
        response += chunk

    # Deconstruct HTTP response
    response_lines = response.decode('utf-8').split('\r\n')
    status_line = response_lines[0]
    status_code = int(status_line.split()[1])

    if status_code == 200:
        print("HTTP request successful.\n")
    else:
        print(f"HTTP request failed with status code {status_code}\n")
        return

    # Save the file
    print("Saving file...\n")
    try:
        with open(file_name, 'w') as f:
            f.write('\n'.join(response_lines[1:]))
    except IOError as e:
        print(f"Error saving file: {e}")
        return

    print("File successfully saved!\n")


URL = "http://www.google.com"
FILE_NAME = "index.html"

if __name__ == '__main__':
    client_request(URL, FILE_NAME)
