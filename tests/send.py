import socket
import struct
from time import sleep

MULTICAST_GROUP = '239.255.0.1'
PORT = 5000

# create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# set the socket to allow broadcasting and reuse the address
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# set the socket to send packets with a defined TTL
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

# Tell the socket to send the multicast packets via the given interface w
# TODO_: Find ip with interface 
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("192.168.248.10"))

# send a multicast message
message = 'Multicast test message'

# receive a multicast message
while True:
    sock.sendto(message.encode(), (MULTICAST_GROUP, PORT))
    sleep(1)