import socket
import struct
import requests

HOST = ''
PORT = 8000
CHUNK_SIZE = 1000
id = 0

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        while True:
            try: 
                client, address = s.recvfrom
                with client:
                    print('Connected by', address)
                    id += 1
                    request = b''
                    # receive request until we find end of headers
                    while b'\r\n\r\n' not in request:
                        data = client.recv(CHUNK_SIZE)
                        if not data:
                            raise Exception('Connection closed unexpectedly')
                        request += data
                    # extract request method, path, and headers
                    method, path, headers = parse_request(request)
                    print(f'Received {method} request for {path}')
                    # follow any redirects using requests
                    url = 'http://localhost:8080' + path
                    # sends an HTTP request to the specified URL, allow_redirects = False -> the request will not automatically follow any redirects that the server might send back.
                    response = requests.request(method, url, headers=headers, allow_redirects=False)
                    # as long as the status code of the response is 301 or 302, which are the HTTP status codes for permanent and temporary redirects, respectively.
                    while response.status_code in (301, 302):
                        # gets the value of the Location header from the response, which contains the URL that the server wants the client to redirect to.
                        url = response.headers['Location']
                        #sends another HTTP request to the new URL obtained from the Location header in oreder to allow the client to manually follow the redirect and control the flow of the program. 
                        response = requests.request(method, url, headers=headers, allow_redirects=False)
                    
                    found = False
                    if response.status_code == requests.codes.ok:
                        found = True
                    bytes_response = response_to_bytes(found, url, response)
                    
                    # send headers response to the client
                    client.sendto(len(bytes_response))
                    
                    # send response body in chunks using RUDP protocol
                    send_rudp_message(client, bytes_response)
                
            except:
                print("error")




def response_to_bytes(found: bool, url: str, res: requests.Response) -> bytes:
    data = b""

    if not found:
        data += struct.pack("B", False)

        message = "The URL \"" + url + "\" not found!".encode()

        data += struct.pack("B", len(message))
        data += message

        return data

    data += struct.pack("B", True)

    headers = res.headers

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


def send_rudp_message(client, message):
    # send message length and message data as separate messages
    while offset < len(message):
        chunk_size = min(CHUNK_SIZE, len(message) - offset)
        chunk_data = response.content[offset:offset+chunk_size]
        send_rudp_message(client, struct.pack('!II', offset, chunk_size) + chunk_data)
        offset += chunk_size
    message_length = len(message)
    client.sendall(struct.pack('!I', message_length))
    client.sendall(message)

if __name__ == '__main__':
    main()