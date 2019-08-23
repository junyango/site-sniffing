import os
import subprocess
import datetime
import logging
import sys
import socket
import argparse
import pandas as pd
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

logging.basicConfig(filename='capture_youtube.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

domain = "youtube"

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--urlfile', help='Input location CSV file containing URLs', required=True)
parser.add_argument('-s', '--savedir', help='Input the directory path to save PCAP files in', required=True)
args = parser.parse_args()

if len(sys.argv) <= 2:
    print("Usage: <url_file> <save_dir>")
    exit(1)

# Initializing adblocker for selenium usage
adPath = "../adblocker/1.511_0"
ad_blockerPath = os.path.abspath(adPath)
chrome_options = Options()
chrome_options.add_argument('load-extension=' + ad_blockerPath)

# Initializing the chrome driver for selenium usage
cdPath = "../chromedriver/chromedriver.exe"
chromeDriverPath = os.path.abspath(cdPath)

# Creating the file path to save the pcap files in
file_path = os.path.join(args.savedir + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
if not os.path.exists(file_path):
    os.makedirs(file_path)

# Read in Dataframes from the CSV file
df = pd.read_csv(args.urlfile)
url_list = df['url'].tolist()


for url in url_list:
    driver = webdriver.Chrome(chromeDriverPath, chrome_options=chrome_options)
    links = []
    videoLinks = []
    driver.get(url)

    elements = driver.find_elements_by_xpath("//*[@href]")
    cdn = ""
    for element in elements:
        if "googlevideo" in element.get_attribute("href"):
            cdn = element.get_attribute("href")
            break
        else:
            continue

    if "https://" in cdn:
        cdn = cdn[8:]
    elif "http://" in cdn:
        cdn = cdn[7:]

    cdn = cdn.split("/")[0]

    try:
        video_server = socket.gethostbyname(cdn)
        logging.info("Currently logging server:  " + str(cdn) + " with IP: " + str(video_server))
    except socket.gaierror as gaie:
        logging.error(str(gaie))
        continue
    except socket.herror as he:
        logging.error(str(he))
        continue

    driver.quit()

    driver = webdriver.Chrome(chromeDriverPath, chrome_options=chrome_options)
    # SNIFFER
    # Declaring variables for the sniffer
    # Capture filter ip_list[0] is taken as the first IP resolved to capture
    # Might not be too perfect in the case
    abspath = os.path.abspath(file_path)
    interface = "Ethernet"
    capture_filter = "host " + video_server
    filename = abspath + "\\" + domain + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

    # Raw capturing
    # command = ["tshark", "-i", interface, "-a", "duration:30", "-f", capture_filter, "-w", filename]
    command = ["tshark", "-i", interface, "-c", "5000", "-f", capture_filter, "-w", filename]
    sts = subprocess.Popen(command, shell=True)
    time.sleep(2)
    driver.get(url)
    driver.switch_to.window(driver.window_handles[1])
    driver.close()
    try:
        sts.wait(timeout=90)
    except subprocess.TimeoutExpired as toe:
        logging.error(str(toe))

    driver.quit()

print("Completed analysis of youtube video packets")
logging.info("Completed analysis of youtube video packets")