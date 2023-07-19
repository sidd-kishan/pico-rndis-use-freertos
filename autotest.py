import socket
import time
def netcat(host, port, content):
    while True:
        time.sleep(0.01)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s.sendall(content.encode())
        data = s.recv(len(content)-2)
        if not data:
            print("")
            break
        print(str(data))
        s.close()

netcat("192.168.7.1", 2542, "getinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfogetinfo\r\n")