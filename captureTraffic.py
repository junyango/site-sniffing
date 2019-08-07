import os
from selenium import webdriver
from bs4 import BeautifulSoup
import subprocess
import psutil
import datetime
import logging
import urllib
import fnmatch
import socket
import random
import sys
import http.client
from os.path import expanduser
from selenium.common.exceptions import InvalidArgumentException
import pandas as pd
from urllib.error import HTTPError
from urllib import request
from selenium.common.exceptions import TimeoutException
from fake_useragent import UserAgent

excel_dir = "./report_unique_servers2.xlsx"
df = pd.read_excel(excel_dir, sheet_name="complete_list")

start_index = int(sys.argv[1])
end_index = int(sys.argv[2])

s = slice(start_index, end_index)

ua = UserAgent()
dictionary = {}
ip_list = df['IP']

# Initializing the dictionary to be able to retrieve the names easily
# Different IP (Key) lead to same Domain (Value)
for index, row in df.iterrows():
    domain = row['Domain']
    ip = row['IP']

    dictionary[ip] = domain


# Declaring global variable since there is only one instance of chromeDriverPath
chromeDriverPath = ""
rootPath = expanduser("D:\\")
sts = ""

logging.basicConfig(filename='capture_traffic.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

file_path = os.path.join("output/normal_traffic/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
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


# Finding the chromedriver path to start selenium web driver
pattern = "chromedriver.exe"
for root, utils, files in os.walk(rootPath):
    for filename in fnmatch.filter(files, pattern):
        chromeDriverPath = (os.path.join(root, filename))


for ip in ip_list[s]:
    # Getting domain
    domain = dictionary[ip]

    # Initializing instance of chrome driver
    driver = webdriver.Chrome(chromeDriverPath)

    # Check if website has http
    if "http" not in domain:
        # appending https:// for urllib
        domain_urllib = "https://" + domain
    else:
        domain_urllib = domain

    # Using fake user agent to prevent HTTP Forbidden error 403
    # Purpose is just to scrap the links from the given domain
    # Able to use random user agent instead of Chrome or actual one in Selenium ChromeDriver
    headers = {'User-Agent': ua.random}
    req = urllib.request.Request(
        domain_urllib,
        data=None,
        headers={'User-Agent': ua.random}
    )

    # Extracting the html from the website
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as httperr:
        logging.error(str(httperr) + str(domain_urllib))
        continue
    except urllib.error.URLError as urle:
        logging.error(str(urle) + str(domain_urllib))
        continue
    except ConnectionResetError as cre:
        logging.error(str(cre) + str(domain_urllib))
        continue
    except TimeoutError as toe:
        logging.error(str(toe) + str(domain_urllib))
    except http.client.HTTPException as httpe:
        logging.error(str(httpe) + str(domain_urllib))

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
    capture_filter = "tcp port 443 and host " + ip
    filename = abspath + "\\" + domain + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

    # Raw capturing
    command = ["tshark", "-i", interface, "-a", "duration:120", "-f", capture_filter, "-w", filename]
    sts = subprocess.Popen(command, shell=True)

    # Requirement for selenium webdriver to have http:// appended infront otherwise webpage wouldnt load
    # Requirement for socket websites to only have the domain without the "/" and https
    # seleniumLink = links to be clicked by selenium
    # socketLink = links to be resolved by resolve_server function

    # Ensuring tshark gets to open before continuing with the code
    while 1:
        tsharkProcess = os.popen("tasklist | findstr tshark").read()
        if tsharkProcess == "":
            continue
        else:
            break

    try :
        driver.get(domain_urllib)
    except InvalidArgumentException as iae:
        logging.info(str(iae) + "Invalid Argument Exception " + str(domain_urllib))
    except TimeoutException as te:
        logging.info(str(te) + "Time Out Exception " + str(domain_urllib))

    # Implementing a do while loop
    # While tshark is still running, continue automating the browser
    while 1:
        tsharkProcess = os.popen("tasklist | findstr tshark").read()
        # Kill all processes when capturing is done
        if tsharkProcess == "":
            # Terminate selenium
            driver.quit()
            logging.info("Done with testing... Killing cmd and dumpcap now...")
            # Remove the instance of chromedriver.exe from running processes
            os.system("taskkill  /F /pid " + str(sts.pid))

            for proc in psutil.process_iter():
                try:
                    # Get process name & pid from process object to kill
                    processName = proc.name()
                    if "dumpcap" in processName:
                        os.system("taskkill  /F /pid " + str(proc.pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            break
        else:
            if len(cleanLinks) > 1:
                link = random.choice(cleanLinks)
                ip_socket = []
                if "http" not in link and ".com" not in link:
                    seleniumLink = "http://" + domain + link
                    socketLink = domain
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

                for ip_test in ip_socket:
                    if ip_test == ip:
                        try:
                            driver.get(seleniumLink)
                            logging.info("Successfully accessed website " + str(seleniumLink))
                        except InvalidArgumentException as iae:
                            logging.info(str(iae) + "Invalid Argument Exception " + str(seleniumLink))
                        except TimeoutException as te:
                            logging.info(str(te) + "Time Out Exception " + str(seleniumLink))
                        finally:
                            break
                    else:
                        continue
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


