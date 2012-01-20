from socket import *
import struct

def getBytes(s, i):
    result = bytearray()
    while len(result) != i:
        result.extend(s.recv(i - len(result)))
    return result

def printBytes(b):
    for i in range(len(b)):
        print("%02x " % b[i], end='')
        if ((i + 1) % 4 == 0):
            print()

s = socket(PF_SYSTEM, SOCK_STREAM, SYSPROTO_CONTROL)

s.connect("org.trustrouter.kext") # s.connect((5, 1))

print("connected to", s.getpeername())

while True:
    id = getBytes(s, struct.calcsize("P"))
    ipHeader = getBytes(s, 40)
    payloadLength = struct.unpack("!H", ipHeader[4:6])[0]
    payload = getBytes(s, payloadLength)

    print("--Header--")
    printBytes(ipHeader)
    print("--Payload--")
    printBytes(payload)
    action = input("Do you trust this RA? (y/N):")
    result=id
    
    if action == "y":
        result.extend(struct.pack("P",1))
    else:
        result.extend(struct.pack("P",0))
    s.send(result)
