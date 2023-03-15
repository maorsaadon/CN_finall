import socket as s
import requests

DOVI_LAST3_ID_DIG = 494
MAOR_LAST3_ID_DIG = 421

IP = '127.0.0.1'
PORT = 20000 + DOVI_LAST3_ID_DIG
CHUNK = 4096


class TCPServer:
    """
    A simple TCP server implementation
    """
    def __init__(self, ip, port):
        # Creates a TCP socket
        self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)
        self.address = ip, port

    def bind(self):
        self.sock.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
        self.sock.bind(self.address)

    def socket(self):
        return self.sock


def download_manager():

    tcp_s = TCPServer(IP, PORT)

    tcp_s.bind()

    tcp_s.socket().listen()

    print("Listening...")

    connection, address = tcp_s.socket().accept()

    print("Connection with client established...\n")

    request = connection.recv(CHUNK)

    print(request)

    print("Got HTTP GET request from client")

    # Extract the file name and host name from the request data
    print("Extracting URL...")
    request_string = request.decode()
    request_lines = request_string.split("\r\n")
    try:
        file_name = request_lines[0][5: -9]
    except IndexError as e:
        print(f"Error extracting file name from request: {e}")
        return
    try:
        host_name = request_lines[1][6:]
    except IndexError as e:
        print(f"Error extracting host name from request: {e}")
        return

    # Construct the URL for the HTTP GET request
    url = f"http://{host_name}/{file_name}"
    print(f"URL for http GET request: {url}.\n")

    # Redirect HTTP GET request to the server
    print("Redirecting HTTP GET request...\n")
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        print(f"Error sending request to server: {e}")
        return
    if 200 <= response.status_code < 300:
        print("GET request redirection was successful.\n")
    # If the GET request still fails, print an error message and return
    else:
        connection.sendto(str(response.status_code).encode() + response.content, address)
        print(f"GET request failed with status code {response.status_code}.\n")
        return

    # Retrieve the file data from the response
    print(f"Getting file: {file_name} from: {host_name}...\n")
    print("Retrieving file data...\n")
    data = str(response.status_code).encode() + response.content

    print("Sending desired data to client...\n")
    try:
        connection.sendto(data, address)
    except ConnectionResetError as e:
        print(f"Error sending response to client: {e}")
        return

    print("File sent.\n")

    print("Closing connection...\n")

    connection.close()

    print("Connection closed.\n")

    return


if __name__ == '__main__':
    download_manager()
