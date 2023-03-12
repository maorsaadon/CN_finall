import socket
import struct
import requests

HOST = ''
PORT = 8000
CHUNK_SIZE = 1000
id = 0


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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
                
                found = False
                if response.status_code == requests.codes.ok:
                    found = True
                bytes_response = response_to_bytes(found, url, response)
                
                # send headers response to the client
                conn.send(len(bytes_response))
                
                # send response body in chunks using RUDP protocol
                

def response_to_bytes(found: bool, url: str, res: requests.Response) -> bytes:
    data = b""

    if not found:
        data += struct.pack("B", False)

        message = "The URL \"" + url + "\" not found!".encode()

        data += struct.pack("B", len(message))
        data += message

        return data

    data += struct.pack("B", True)

    headers = build_response_headers(res)

    data += struct.pack("I", len(headers.encode()))
    data += headers.encode()

    data += struct.pack("I", len(res.encoding.encode()))
    data += res.encoding.encode()

    data += struct.pack("I",  len(res.status_code))
    data += res.status_code.encode()

    data += struct.pack("I", len(res.content.encode()))
    data += res.content.encode()

    return data

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

if __name__ == '__main__':
    main()
    