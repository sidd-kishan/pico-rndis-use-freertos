import socket
import time

UDP_IP = "192.168.7.1"
UDP_PORT = 2542
MESSAGE = b"getinfo\n"

print("UDP target IP: %s" % UDP_IP)
print("UDP target port: %s" % UDP_PORT)
print("message: %s" % MESSAGE)

while True:
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
    data = sock.recv(1024)
    sock.close()
    print(data)
    time.sleep(0.1)