import os
from selenium import webdriver
import subprocess
import datetime
import logging
import socket
import random
import urllib
from fake_useragent import UserAgent
import urllib.request
from urllib.request import Request, urlopen
import urllib.error
import argparse
from bs4 import BeautifulSoup
import sys
from selenium.common.exceptions import InvalidArgumentException
import pandas as pd
from selenium.common.exceptions import TimeoutException

excel_dir = "./report_unique_servers2.xlsx"
print("Reading from excel file now for the list of sites to test...")
df = pd.read_excel(excel_dir, sheet_name="complete_list")

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--start', help='Start index of the csv file')
parser.add_argument('-e', '--end', help='End index of the csv file')
args = parser.parse_args()

if len(sys.argv) <= 2:
    print("Usage: <start_index> <end_index>")
    exit(1)

start_index = int(args.start)
end_index = int(args.end)

# To be applied to the CSV file
s = slice(start_index, end_index)

dictionary = {}
ip_list = df['IP']
ua = UserAgent()

# Initializing the dictionary to be able to retrieve the names easily
# Different IP (Key) lead to same Domain (Value)
for index, row in df.iterrows():
    domain = row['Domain']
    ip = row['IP']

    dictionary[ip] = domain

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
# Getting the abs path of chromedriver for selenium automation
cdPath = "../chromedriver/chromedriver.exe"
chromeDriverPath = os.path.abspath(cdPath)
driver = webdriver.Chrome(chromeDriverPath)


for ip in ip_list[s]:
    # Getting domain
    domain = dictionary[ip]

    # Check if website has http
    if "http" not in domain:
        # appending https:// for urllib
        domain_urllib = "https://" + domain
    else:
        domain_urllib = domain

    headers = {'User-Agent': ua.random}
    req = Request(
        domain_urllib,
        headers={'User-Agent': ua.random}
    )

    # Trying to open the URL to scrape HTML
    try:
        resp = urlopen(req).read()
    except urllib.error.HTTPError as httpe:
        logging.error(str(httpe) + " for " + domain_urllib)
        continue
    except urllib.error.URLError as urle:
        logging.error(str(urle) + " for " + domain_urllib)
        continue

    soup = BeautifulSoup(resp, "html.parser")
    cleanLinks = []
    for link in soup.find_all('a', href=True):
        if "javascript" not in link or "#" not in link:
            cleanLinks.append(link["href"])

    # SNIFFER
    # Declaring variables for the sniffer
    # Capture filter ip_list[0] is taken as the first IP resolved to capture
    # Might not be too perfect in the case
    abspath = os.path.abspath(file_path)
    interface = "Wi-Fi"
    capture_filter = "tcp port 443 and host " + ip
    filename = abspath + "\\" + domain + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"

    # Raw capturing
    # command = ["tshark", "-i", interface, "-a", "duration:120", "-f", capture_filter, "-w", filename]
    command = ["tshark", "-i", interface, "-c", "5000", "-f", capture_filter, "-w", filename]
    sts = subprocess.Popen(command, shell=True)

    while 1:
        tshark = os.popen("tasklist | findstr tshark").read()
        if tshark == "":
            print("Tshark has stopped")
            break
        else:
            if len(cleanLinks) > 1:
                link = random.choice(cleanLinks)
                print(link + " has been chosen")
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
                            continue
                        except TimeoutException as te:
                            logging.info(str(te) + "Time Out Exception " + str(seleniumLink))
                            continue
                    else:
                        continue
            else:
                continue

# Terminate selenium
driver.quit()
logging.info("Done with testing... Killing cmd and dumpcap now...")



