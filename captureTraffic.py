import os
from selenium import webdriver
from bs4 import BeautifulSoup
import socket
import subprocess
import psutil
import datetime
import logging
import urllib
import fnmatch
from os.path import expanduser
from selenium.common.exceptions import InvalidArgumentException
import pandas as pd
from urllib.error import HTTPError
from urllib import request
from selenium.common.exceptions import TimeoutException

excel_dir = "C:/Users/ju-ny/Desktop/FYPlearn/report_unique_servers2.xlsx"
df = pd.read_excel(excel_dir, sheet_name="complete_list")

domains = []

domain_col = df['Domain']

for row in domain_col:
    if row not in domains:
        domains.append(row)
    else:
        continue

# Declaring global variable since there is only one instance of chromeDriverPath
chromeDriverPath = ""
rootPath = expanduser("~")
sts = ""

logging.basicConfig(filename='application.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

file_path = os.path.join("output/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
if not os.path.exists(file_path):
    os.makedirs(file_path)


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


# Finding the chromedriver path to start selenium web driver
pattern = "chromedriver.exe"
for root, utils, files in os.walk(rootPath):
    for filename in fnmatch.filter(files, pattern):
        chromeDriverPath = (os.path.join(root, filename))


for website in domains:
    driver = webdriver.Chrome(chromeDriverPath)
    # Check if website has http
    if "http" not in website:
        # appending https:// for urllib
        domain_urllib = "https://" + website
    else:
        domain_urllib = website

    domain_socket = clean_domain(website)

    # Creating a directory for output
    datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "/" + domain_socket
    file_dir = os.path.join(file_path + "/" + domain_socket)
    if os.path.exists(file_dir):
        os.mkdir(file_dir)

    # Getting list of possible ip from the particular domain
    ip_list = []
    try:
        socket_info = socket.getaddrinfo(domain_socket, None)
    except socket.gaierror as e:
        logging.error(str(e) + str(domain_socket))
        continue

    for info in socket_info:
        ip_list.append(info[4][0])

    # Extracting the html from the website
    try:
        response = urllib.request.urlopen(domain_urllib)
    except urllib.error.HTTPError as e:
        logging.error(str(e) + str(domain_urllib))
        continue
    except urllib.error.URLError as e:
        logging.error(str(e) + str(domain_urllib))
        continue

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

    # SNIFFER
    # Declaring variables for the sniffer
    # Capture filter ip_list[0] is taken as the first IP resolved to capture
    # Might not be too perfect in the case
    abspath = os.path.abspath(file_path)
    interface = "Ethernet"
    capture_filter = "tcp port 443 and host " + ip_list[0]
    web_name = domain_socket.split(".")[0]
    filename = abspath + "\\" + web_name + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

    # Raw capturing
    command = ["tshark", "-i", interface, "-c 10000", "-f", capture_filter, "-w", filename]
    sts = subprocess.Popen(command, shell=True)
    driver.get(domain_urllib)

    # Requirement for selenium webdriver to have http:// appended infront otherwise webpage wouldnt load
    # Requirement for socket websites to only have the domain without the "/" and https
    # seleniumLink = links to be clicked by selenium
    # socketLink = links to be resolved by resolve_server function

    countLinks = 0

    # Providing 1 avenue of termination of breaking the while loop
    for link in cleanLinks:
        tsharkProcess = os.popen("tasklist | findstr tshark").read()
        # Kill all processes when capturing is done
        if tsharkProcess == "":
            # Terminate selenium
            driver.quit()
            logging.info("Done with testing... Killing cmd and dumpcap now...")
            # Remove the instance of chromedriver.exe from running processes
            os.system("taskkill  /F /pid "+str(sts.pid))

            for proc in psutil.process_iter():
                try:
                    # Get process name & pid from process object to kill
                    processName = proc.name()
                    if "dumpcap" in processName:
                        os.system("taskkill  /F /pid "+str(proc.pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            break

        ip_socket = []
        if "http" not in link and ".com" not in link:
            seleniumLink = "http://" + domain_socket + link
            socketLink = domain_socket
        else:
            seleniumLink = link
            socketLink = clean_domain(link)

        try:
            socket_info = socket.getaddrinfo(socketLink, None)
        except socket.gaierror as e:
            logging.error(str(e) + " error for " + str(socketLink))
            continue
        except UnicodeError as e:
            logging.error(str(e) + " error for " + str(socketLink))
            continue

        for info in socket_info:
            ip_socket.append(info[4][0])

        for ip in ip_socket:
            if ip in ip_list:
                try:
                    driver.get(seleniumLink)
                    logging.info("Successfully accessed website " + str(seleniumLink))
                    countLinks = countLinks + 1
                except InvalidArgumentException as iae:
                    logging.info(str(iae) + "Invalid Argument Exception " + str(seleniumLink))
                except TimeoutException as te:
                    logging.info(str(te) + "Time Out Exception " + str(seleniumLink))
                finally:
                    break
            else:
                continue

    # Terminate selenium
    driver.quit()
    logging.info("Done with testing... Killing cmd and dumpcap now...")

    # Remove the instance of chromedriver.exe from running processes
    os.system("taskkill  /F /pid "+str(sts.pid))

    for proc in psutil.process_iter():
        try:
            # Get process name & pid from process object to kill
            processName = proc.name()
            if "dumpcap" in processName:
                os.system("taskkill  /F /pid "+str(proc.pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


