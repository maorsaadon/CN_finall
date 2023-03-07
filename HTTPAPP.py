import socket
import struct
import requests

HOST = ''
PORT = 8000
CHUNK_SIZE = 1024

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                request = b''
                # receive request until we find end of headers
                while b'\r\n\r\n' not in request:
                    data = conn.recv(CHUNK_SIZE)
                    if not data:
                        raise Exception('Connection closed unexpectedly')
                    request += data
                # extract request method, path, and headers
                method, path, headers = parse_request(request)
                print(f'Received {method} request for {path}')
                # follow any redirects using requests
                url = 'http://localhost:8080' + path
                response = requests.request(method, url, headers=headers, allow_redirects=False)
                while response.status_code in (301, 302):
                    url = response.headers['Location']
                    response = requests.request(method, url, headers=headers, allow_redirects=False)
                # send response headers
                response_headers = build_response_headers(response)
                conn.sendall(response_headers)
                # send response body in chunks using RUDP protocol
                send_rudp_message(conn, struct.pack('!I', len(response.content)))
                offset = 0
                while offset < len(response.content):
                    chunk_size = min(CHUNK_SIZE, len(response.content) - offset)
                    chunk_data = response.content[offset:offset+chunk_size]
                    send_rudp_message(conn, struct.pack('!II', offset, chunk_size) + chunk_data)
                    offset += chunk_size

def parse_request(request):
    request_str = request.decode('utf-8')
    request_lines = request_str.split('\r\n')
    method, path, _ = request_lines[0].split(' ')
    headers = {}
    for line in request_lines[1:]:
        if line:
            name, value = line.split(': ')
            headers[name] = value
    return method, path, headers

def build_response_headers(response):
    headers = [
        f'HTTP/1.1 {response.status_code} {response.reason}',
        f'Content-Type: {response.headers.get("Content-Type", "application/octet-stream")}',
        f'Content-Length: {len(response.content)}',
        '',
        ''
    ]
    return '\r\n'.join(headers).encode('utf-8')

def send_rudp_message(conn, message):
    # send message length and message data as separate messages
    message_length = len(message)
    conn.sendall(struct.pack('!I', message_length))
    conn.sendall(message)

if __name__ == '__main__':
    main()
