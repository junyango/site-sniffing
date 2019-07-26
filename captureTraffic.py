import os
from selenium import webdriver
from bs4 import BeautifulSoup
import socket
import subprocess
import signal
import psutil
import datetime
import logging
import urllib
import fnmatch
import sys
from os.path import expanduser
from selenium.common.exceptions import InvalidArgumentException

website = "https://facebook.com"

# Declaring global variable since there is only one instance of chromeDriverPath
chromeDriverPath = ""
rootPath = expanduser("~")

logging.basicConfig(filename='application.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')


def clean_domain(url):
    if "https://" in url:
        result = url[8:]
    elif "http://" in url:
        result = url[7:]
    else:
        result = url

    if result[0:4] == "www.":
        result = result[4:]

    if "/" in result:
        result = result.split("/")[0]

    return result


domain = clean_domain(website)
# Creating a directory for output
datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "/" + domain

file_path = os.path.join("output/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "/" + domain)
if not os.path.exists(file_path):
    os.makedirs(file_path)

# Getting list of possible ip from the particular domain
ip_list = []
socket_info = socket.getaddrinfo(domain, None)
for info in socket_info:
    ip_list.append(info[4][0])

# Extracting the html from the website
response = urllib.request.urlopen(website)

# Scrapping the links from the html page
links = []
cleanLinks = []
soup = BeautifulSoup(response, features="lxml")
for link in soup.findAll('a', href=True):
    links.append(link["href"])

# Removing "#" from the links
for link in links:
    if "#" not in link:
        cleanLinks.append(link)

# Finding the chromedriver path to start selenium web driver
pattern = "chromedriver.exe"
for root, utils, files in os.walk(rootPath):
    for filename in fnmatch.filter(files, pattern):
        chromeDriverPath = (os.path.join(root, filename))


# SNIFFER
# Declaring variables for the sniffer
# Capture filter ip_list[0] is taken as the first IP resolved to capture
# Might not be too perfect in the case
abspath = os.path.abspath(file_path)
interface = "Ethernet"
capture_filter = "tcp port 443 and host " + ip_list[0]
web_name = domain.split(".")[0]
filename = abspath + "\\" + web_name + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

# Raw capturing
command = ["tshark", "-i", interface, "-c 10000", "-f", capture_filter, "-w", filename]
sts = subprocess.Popen(command, shell=True)

driver = webdriver.Chrome(chromeDriverPath)
driver.get(website)

# Requirement for selenium webdriver to have http:// appended infront otherwise webpage wouldnt load
# Requirement for socket websites to only have the domain without the "/" and https
# seleniumLink = links to be clicked by selenium
# socketLink = links to be resolved by resolve_server function

countLinks = 0

# Providing 1 avenue of termination of breaking the while loop
for link in cleanLinks:
    tsharkProcess = os.popen("tasklist | findstr tshark").read()
    if tsharkProcess == "":
        driver.quit()
        sys.exit()

    ip_socket = []
    if "http" not in link and ".com" not in link:
        seleniumLink = "http://" + domain + link
        socketLink = domain
    else:
        seleniumLink = link
        socketLink = clean_domain(link)

    socket_info = socket.getaddrinfo(socketLink, None)
    for info in socket_info:
        ip_socket.append(info[4][0])

    for ip in ip_socket:
        if ip in ip_list:
            try:
                driver.get(seleniumLink)
                logging.info("Successfully accessed website " + str(seleniumLink))
                countLinks = countLinks + 1
            except InvalidArgumentException as e:
                logging.info(str(e) + "Invalid Argument Exception" + str(seleniumLink))
            break
        else:
            continue


logging.info("Done with testing... Killing cmd and dumpcap now...")
os.kill(sts.pid, signal.SIGTERM)

for proc in psutil.process_iter():
    try:
        # Get process name & pid from process object to kill
        processName = proc.name()
        if "dumpcap" in processName:
            os.kill(proc.pid, signal.SIGTERM)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

# Remove the instance of chromedriver.exe from running processes
driver.quit()



