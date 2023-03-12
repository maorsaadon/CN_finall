import socket, glob, json
from scapy.all import DNS

def get_bit(value: int, bit_index: int) -> int:
    """
    Get the bit at the given index in the binary representation of the given value.
    
    Args:
        value (int): The value to get the bit from.
        bit_index (int): The index of the bit to get, where 0 is the least significant bit.
    
    Returns:
        int: The value of the bit at the given index (0 or 1).
    """
    bit_mask = 1 << bit_index
    bit_value = (value & bit_mask) >> bit_index
    return bit_value


def get_flags_by_bit(flags: bytes) -> bytes:
    """
    Decode the DNS response flags from a two-byte value.
    
    Args:
        flags (bytes): The two-byte value containing the response flags.
    
    Returns:
        bytes: The decoded response flags as a two-byte value.
    """
    first_byte = flags[0]
    second_byte = flags[1]

    # Decode bits in first byte
    QR = get_bit(first_byte, 0)
    OPCODE = ''.join(str(get_bit(first_byte, i)) for i in range(1, 5))
    AA = get_bit(first_byte, 5)
    TC = get_bit(first_byte, 6)
    RD = get_bit(first_byte, 7)

    # Decode bits in second byte
    RA = get_bit(second_byte, 0)
    Z = ''.join(str(get_bit(second_byte, i)) for i in range(1, 4))
    RCODE = ''.join(str(get_bit(second_byte, i)) for i in range(4, 8))

    # Combine decoded bits into two-byte value
    response_flags = int(f"{QR}{OPCODE}{AA}{TC}{RD}{RA}{Z}{RCODE}", 2).to_bytes(2, byteorder='big')

    return response_flags



def get_flags (flags):

    # Set the values of flags that don't depend on the input flags
    QR, AA, TC, RD, RA, Z, RCODE = '1', '1', '0', '0', '0', '000', '0000'

    # Extract the first byte from the input flags
    first_byte = bytes(flags[:1])

    # Extract the OPCODE flag from the first byte
    OPCODE = ''
    for bit in range(1, 5):
        # The ord function returns the integer that represents the character - ASCII
        # The first bit is the QR Flag
        OPCODE += str(ord(first_byte) & (1 << bit))

    # Assemble the responseFlag byte string using the set flag values
    responseFlag = int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

    return responseFlag



def get_question_domain(data):
    """
    This function takes in a DNS query message in binary format and extracts the domain name and question type from it.

    Args:
    data: A binary string representing the DNS query message.

    Returns:
    A tuple containing the domain name (as a list of strings) and the question type (as a binary string).
    """

    # Initialize variables
    state = 0
    expected_length = 0
    domain_string = ''
    domain_parts = []
    letters = 0
    index = 0 

    # Loop through the message and extract the domain name and question type
    for byte in data:
        if state == 1:
            # Read the domain name
            if byte != 0:
                domain_string += chr(byte)
            letters += 1
            if letters == expected_length:
                domain_parts.append(domain_string)
                domain_string = ''
                state = 0
                letters = 0
            if byte == 0:
                domain_parts.append(domain_string)
                # We have finished reading the domain name
                break
        else:
            # Read the length of the next segment of the domain name
            state = 1
            expected_length = byte

        index += 1

    # Extract the question type
    question_type = data[index:index+2]

    return (domain_parts, question_type)


def load_zone():
    """
    Load DNS zones from JSON files and return a dictionary with zone names as keys and zone data as values.

    Returns:
    dict: A dictionary with zone names as keys and zone data as values.
    """
    jsonZone = {}
    zoneFiles = glob.glob('zones/*.zone')
    
    # Iterate over all zone files and load the data into a dictionary
    for zone in zoneFiles:
        with open(zone) as zoneData:
            data = json.load(zoneData)

            zoneName = data["$origin"]
            jsonZone[zoneName] = data

    return jsonZone



def get_zone(domainName):
    '''
    Retrieves the zone data for the given domain name by concatenating the domain name and
    querying the global zoneData dictionary.

    Parameters:
        domainName (list): A list of domain name parts, e.g. ["www", "example", "com"].

    Returns:
        The zone data for the given domain name, retrieved from the global zoneData dictionary.
    '''
    global zoneData 

    zoneName = '.'.join(domainName)

    return zoneData[zoneName]
  

def get_records(data):
    """
    Get resource records from DNS query data.

    Parameters:
    data (bytes): The DNS query data.

    Returns:
    tuple: A tuple containing the resource records in the zone that match the query type, the query type and the domain name.

    """
    domainName, questionType = get_question_domain(data)

    # Translate query type to abbreviation
    qt = ''
    if questionType == b'\x00\x01':
        qt = 'A'

    # Get the zone for the domain name
    zone = get_zone(domainName)

    # Return the resource records, query type and domain name
    return (zone[qt], qt, domainName)



def build_query(domainName, recordsType):
    """
    Builds a DNS query packet using the given domain name and record type.

    Args:
    domainName (list): A list containing the labels of the domain name to query.
    recordsType (str): The type of DNS record to query for.

    Returns:
    bytes: The DNS query packet in bytes.

    """
    queryByte = b''

    # Build the query packet for each label in the domain name
    for level in domainName:
        queryByte += bytes([len(level)])  # Add the label length to the packet

        # Add each character of the label to the packet
        for letter in level:
            queryByte += ord(letter).to_bytes(1, byteorder="big")

    # Add the record type to the packet
    if(recordsType == 'A'):
        queryByte += (1).to_bytes(2, byteorder="big")

    # Add the record class (always IN) to the packet
    queryByte += (1).to_bytes(2, byteorder="big")

    return queryByte

def record_bytes(domainName, recordType, recordTtl, recordValue):
    """
    Returns the record bytes for a given domain name, record type, record TTL, and record value.

    Args:
        domainName (list): The domain name for the record.
        recordType (str): The record type, e.g. "A".
        recordTtl (int): The record time-to-live in seconds.
        recordValue (str): The value of the record.

    Returns:
        bytes: The record bytes.

    """

    # The first two bytes in the record bytes should be the compression pointer for the domain name
    # This is set to 0xc00c because it points to the beginning of the answer section of the DNS message
    recordBytes = b'\xc0\x0c'

    # If the record type is A, add the bytes 0x00 and 0x01 to indicate an IPv4 address
    if recordType == 'A':
        recordBytes += bytes([0]) + bytes([1])

    # Add the bytes 0x00 and 0x01 to indicate an internet address class
    recordBytes += bytes([0]) + bytes([1])

    # Add the record's TTL in big-endian format
    recordBytes += int(recordTtl).to_bytes(4, byteorder='big')

    # If the record type is A, add the bytes 0x00 and 0x04 to indicate the length of the IPv4 address
    if recordType == 'A':
        recordBytes += bytes([0]) + bytes([4])

    # Add the bytes of the record value, which is an IPv4 address
    for segment in recordValue.split('.'):
        recordBytes += bytes([int(segment)])

    return recordBytes

    
def build_response(data):
    # Get the Transaction ID
    TransactionID = data[:2]

    # Get the Flags
    Flags = get_flags(data[2:4])

    # Set the Question Count to 1
    QDCOUNT = b'\x00\x01'

    # Get the Answer Count
    records, recordsType, domainName = get_records(data[12:])
    ANCOUNT = len(records).to_bytes(2, byteorder= "big")

    # Set the Name Server Count to 0
    NSCOUNT = (0).to_bytes(2, byteorder= "big")

    # Set the Additional Records Count to 0
    ARCOUNT = (0).to_bytes(2, byteorder= "big")

    # Merge all the headers
    DNSHeader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # Create the DNS Body
    DNSBody = b''

    # Build the DNS Query
    DNSQuery = build_query(domainName, recordsType)

    # Build the response records
    for record in records:
        DNSBody += record_bytes(domainName, recordsType, record['ttl'], record['value'])

    # Combine the DNS Header, DNS Query, and DNS Body to form the complete packet
    packet = DNSHeader + DNSQuery + DNSBody

    # Print a summary of the packet (for debugging purposes)
    print(DNS(packet).summary())

    return packet


if __name__ == '__main__':
    # set the port and IP address for the server
    port = 53
    ip = '127.0.0.1'

    # load the zone data from file
    zoneData = load_zone()

    # create a UDP socket and bind it to the specified IP address and port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))

    # start listening for incoming DNS requests
    while 1:
        # receive the DNS query data and the address of the client making the request
        data, addr = sock.recvfrom(512)

        # generate a response to the DNS query
        response = build_response(data)

        # send the response back to the client
        sock.sendto(response, addr)







