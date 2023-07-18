import socket
import time
def netcat(host, port, content):
    while True:
        time.sleep(0.010)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s.sendall(content.encode())
        data = s.recv(100)
        if not data:
            print("")
            break
        print(str(data))
        s.close()

netcat("192.168.7.1", 2542, "getinfo\r\n")