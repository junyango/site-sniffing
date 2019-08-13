import os
import subprocess
import datetime
import logging
import random
import sys
import socket

from selenium import webdriver
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

if len(sys.argv) <= 2:
    print("Usage: <domain> <iterations>")
    exit(1)

logging.basicConfig(filename='capture_youtube.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

domain = sys.argv[1]
iterations = int(sys.argv[2])

cdPath = "../chromedriver/chromedriver.exe"

chromeDriverPath = os.path.abspath(cdPath)

file_path = os.path.join("output/youtube_traffic/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
if not os.path.exists(file_path):
    os.makedirs(file_path)

count = 0

while count < iterations:
    # Initializing instance of chrome driver
    driver = webdriver.Chrome(chromeDriverPath)

    links = []
    videoLinks = []

    if "http" not in domain:
        seleniumLink = "https://" + domain
    else:
        seleniumLink = domain

    driver.get(seleniumLink)
    WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.ID, "video-title")))
    links = driver.find_elements_by_id("video-title")

    for x in links:
        videoLinks.append(x.get_attribute("href"))

    chosen_link = random.choice(videoLinks)
    driver.get(chosen_link)

    cdn = ""
    elems = driver.find_elements_by_xpath("//*[@href]")
    for elem in elems:
        if "googlevideo" in elem.get_attribute("href"):
            cdn = elem.get_attribute("href")
            break
        else:
            continue

    if "https://" in cdn:
        cdn = cdn[8:]
    elif "http://" in cdn:
        cdn = cdn[8:]

    cdn = cdn.split("/")[0]
    print(cdn)

    try:
        video_server = socket.gethostbyname(cdn)
        logging.info("Currently logging server:  " + str(cdn) + " with IP: " + str(video_server))
    except socket.gaierror as gaie:
        logging.error(str(gaie))
    except socket.herror as he:
        logging.error(str(he))

    # SNIFFER
    # Declaring variables for the sniffer
    # Capture filter ip_list[0] is taken as the first IP resolved to capture
    # Might not be too perfect in the case
    abspath = os.path.abspath(file_path)
    interface = "Ethernet"
    capture_filter = "host " + video_server
    print(capture_filter)
    filename = abspath + "\\" + domain + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

    # Raw capturing
    command = ["tshark", "-i", interface, "-a", "duration:30", "-f", capture_filter, "-w", filename]
    sts = subprocess.Popen(command, shell=True).wait()

    # Terminate selenium
    driver.quit()
    logging.info("Done with testing... Killing cmd and dumpcap now...")

    count += 1


print("Completed analysis of youtube video packets")
logging.info("Completed analysis of youtube video packets")
