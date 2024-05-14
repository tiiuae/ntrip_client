import socket
import struct
from time import sleep

MULTICAST_GROUP = '239.255.0.1'
PORT = 5000

# create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# set the socket to allow broadcasting and reuse the address
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)w

# bind the socket to the multicast port
sock.bind(('', PORT))

# add the multicast group to the socket, any interface not a specific interface
group = socket.inet_aton(MULTICAST_GROUP)
mreq = struct.pack('4sL', group, socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# receive a multicast message
while True:
    data, address = sock.recvfrom(1024)
    print('Received message from {}: {}'.format(address, data.decode()))