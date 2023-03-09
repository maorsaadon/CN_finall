import socket, glob, json
from scapy.all import DNS

def get_bit (value, bit_index):
    return (value >> bit_index) & 1

def getFlagsByBit (flags):

    first_byte = bytes(flags[:1])
    second_byte = bytes(flags[1:2])

    QR  = get_bit(first_byte,0)

    OPCODE = ''
    for bit in range (1,5):
        #the ord function returns the integer that represents the character - ASCI
        #the first bit is the QR Flag
        OPCODE += str(ord(first_byte)&(1<<bit)) 

    #NEED TO CHECK THESE FLAGS!!! -
    #TO DO MASK FOR EVERY FLAG HERE
    AA = get_bit(first_byte,5)
    TC = get_bit(first_byte,6)
    RD = get_bit(first_byte,7)       

    #second_byte
    RA = get_bit(second_byte,0)

    Z = ''
    for bit in range (1,4):
        #the ord function returns the integer that represents the character - ASCI
        #the first bit is the QR Flag
        Z += str(ord(second_byte)&(1<<bit)) 

    #CHECK THIS MASKING!!!
    RCODE = ''
    for bit in range (1,4):
        #the ord function returns the integer that represents the character - ASCI
        #the first bit is the QR Flag
        RCODE += str(ord(second_byte)&(1<<bit))

    responseFlag = int(QR+ OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

    return responseFlag

def get_flags (flags):

    first_byte = bytes(flags[:1])

    QR  = '1'

    OPCODE = ''
    for bit in range (1,5):
        #the ord function returns the integer that represents the character - ASCI
        #the first bit is the QR Flag
        OPCODE += str(ord(first_byte)&(1<<bit)) 

    #NEED TO CHECK THESE FLAGS!!! -
    #TO DO MASK FOR EVERY FLAG HERE
    AA = '1'
    TC = '0'
    RD = '0'       

    #second_byte
    RA = '0'
    Z = '000'
    RCODE = '0000'

    responseFlag = int(QR+ OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

    return responseFlag

def get_question_domain(data):

    state = 0
    exceptedLength = 0
    domainString = ''
    domainParts =[]
    letters = 0
    index = 0 

    for byte in data:
        if state == 1:
            if byte != 0:
                domainString += chr(byte)
            letters += 1
            if letters == exceptedLength:
                domainParts.append(domainString)
                domainString = ''
                state = 0
                letters = 0
            if byte == 0:
                domainParts.append(domainString)
                #we have done to read the domain's name
                break
        else:
            state = 1
            exceptedLength = byte

        index += 1

    quetionType = data[index:index+2]

    return (domainParts, quetionType)

def load_zone():
    jsonZone = {}
    zoneFiles = glob.glob('zones/*.zone')
    
    for zone in zoneFiles:
        with open(zone) as zoneData:
            data = json.load(zoneData)

            zoneName = data["$origin"]
            jsonZone[zoneName] = data

    return jsonZone

def get_zone(domainName):
    global zoneData 

    zoneName = '.'.join(domainName)

    return zoneData[zoneName]   

def get_records(data):
    domainName, questionType = get_question_domain(data)

    qt = ''
    if questionType == b'\x00\x01':
        qt = 'A'
    
    zone = get_zone(domainName)

    return (zone[qt], qt, domainName)

def build_query(domainName, recordsType):
    queryByte = b''

    for level in domainName:
        queryByte += bytes([len(level)])

        for letter in level:
            queryByte += ord(letter).to_bytes(1, byteorder= "big")


    if(recordsType == 'A'):
        queryByte += (1).to_bytes(2, byteorder= "big")
        
    queryByte += (1).to_bytes(2, byteorder= "big")

    return queryByte

def record_bytes(domainName,recordType,recordTtl, recordValue):
    recordBytes = b'\xc0\x0c' 

    if recordType == 'A':
        recordBytes += bytes([0]) + bytes([1])

    recordBytes += bytes([0]) + bytes([1])
    recordBytes += int(recordTtl).to_bytes(4,byteorder='big')

    if recordType == 'A':
        recordBytes += bytes([0]) + bytes([4])

    for segment in recordValue.split('.'):
        recordBytes += bytes([int(segment)])
    
    return recordBytes
    
def build_response(data):
    #get the Transaction ID
    TransactionID = data[:2]

    #get the Flags
    Flags = get_flags(data[2:4])

    #get the Question Count - allways equals to 1
    QDCOUNT = b'\x00\x01'

    #get the Answer Count 
    ANCOUNT = len(get_records(data[12:])[0]).to_bytes(2, byteorder= "big")

    #get the Name Server Count
    #NSCOUNT = b'\x00\x00'
    NSCOUNT = (0).to_bytes(2, byteorder= "big")

    #get the Additional Records Count
    #ARCOUNT = b'\x00\x00'
    ARCOUNT = (0).to_bytes(2, byteorder= "big")

    #merge all the headers
    DNSHeader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    #create the DNS Body
    DNSBody = b''

    #get the answer for the query
    records, recordsType, domainName = get_records(data[12:])

    DNSQuery = build_query(domainName, recordsType)

    for record in records:
        DNSBody += record_bytes(domainName,recordsType,record['ttl'],record['value'])

    packet = DNSHeader + DNSQuery + DNSBody 
    print(DNS(packet).summary())
    return packet


if __name__ == '__main__':
    port = 53
    ip = '127.0.0.1'

    zoneData = load_zone()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))


    while 1:
        #512 - for udp msg
        data, addr = sock.recvfrom(512)
        response = build_response(data)
        print(response)
        sock.sendto(response, addr)




