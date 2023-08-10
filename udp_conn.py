import socket
import time
from collections import Counter

topten={}
def parse_wifi_info(input_string):
    # Split the input_string using the delimiters to extract individual parts
    parts = input_string.strip().split()
    ssid = None
    rssi = None
    chan = None
    mac = None
    sec = None

    for i in range(len(parts)):
        part = parts[i].decode('utf-8', errors='ignore')  # Convert bytes to string
        if part == 'ssid:':
            ssid = parts[i + 1].decode('utf-8', errors='ignore')
        elif part == 'rssi:':
            rssi = int(parts[i + 1].decode('utf-8', errors='ignore'))
        elif part == 'chan:':
            chan = int(parts[i + 1].decode('utf-8', errors='ignore'))
        elif part == 'mac:':
            mac = parts[i + 1].decode('utf-8', errors='ignore')
        elif part == 'sec:':
            sec = int(parts[i + 1].decode('utf-8', errors='ignore'))

    if ssid is not None and rssi is not None and chan is not None and mac is not None and sec is not None:
        return {'ssid': ssid, 'rssi': rssi, 'chan': chan, 'mac': mac, 'sec': sec}
    else:
        return None

def create_top_ten_dict(log):
    global topten
    ssid_list = parse_wifi_info(log)
    #ssid_counter = Counter(ssid_list)
    #top_ten_dict = dict(ssid_counter.most_common(10))
    topten[ssid_list['ssid']]=ssid_list
    return topten



#UDP_IP = "192.168.7.1"
#UDP_PORT = 2542
#MESSAGE = b"getinfo\n"

#print("UDP target IP: %s" % UDP_IP)
#print("UDP target port: %s" % UDP_PORT)
#print("message: %s" % MESSAGE)

def netcat(host, port, content):
    total_ap=0
    while True:
        time.sleep(0.1)
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
        sock.sendto(content, (host, int(port)))
        data = sock.recv(100)
        if not data:
            print("")
            break
        sock.close()
        top_ten_ssid_dict=create_top_ten_dict(data)
        if total_ap<len(top_ten_ssid_dict):
            print(top_ten_ssid_dict)
            total_ap=len(top_ten_ssid_dict)

netcat("192.168.7.1", 2542, b'getinfo\n')