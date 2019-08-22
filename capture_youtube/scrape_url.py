from selenium import webdriver
from selenium.common.exceptions import *
import os
import pandas as pd
import random
import time
import logging
import argparse
import sys
from datetime import datetime

youtube_url = "http://www.youtube.com"
datetime_now = datetime.now()

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--category', help='Input location for file categories')
parser.add_argument('-i', '--iterations', help='Input amount of URLs to scrape', required=True)
parser.add_argument('-s', '--savedir', help='Input the directory path to save csv file in', required=True)
args = parser.parse_args()

if len(sys.argv) <= 3:
    print("Usage: <category_file> <num_url_scrape> <save_dir>")
    exit(1)

if not os.path.exists(args.savedir):
    os.mkdir(args.savedir)

output_prefix = args.savedir

logging.basicConfig(filename='scrap_url.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

iterations = int(args.iterations)

# Initializing how the data frame should look like
df = pd.DataFrame(columns=['url'])

# Getting the abs path of chromedriver for selenium automation
cdPath = "../chromedriver/chromedriver.exe"
chromeDriverPath = os.path.abspath(cdPath)
driver = webdriver.Chrome(chromeDriverPath)

# Temporarily using a categorical text folder
f = open("categories.txt", "r")
categories = f.read().splitlines()
f.close()

# Initializing the chrome path driver
each_category = int(iterations/len(categories))
print("There are a total of " + str(len(categories)) + " categories" + " and each category will have "
      + str(each_category) + " URLs")
logging.info(str(len(categories)) + " categories and " + str(each_category) + " URLs")

url_list = []

logging.info("Beginning testing...")

# Looping through all the categories given in the text file
for category in categories:
    url_category = []
    # Looping for iterations splitted evenly between the categories
    driver.get(youtube_url)
    driver.find_element_by_id("search").send_keys(category)
    driver.find_element_by_id("search-icon-legacy").click()

    while len(url_category) < each_category:
        try:
            elements = driver.find_elements_by_xpath("//a[@href]")
        except NoSuchElementException as nsee:
            logging.exception(str(nsee) + " NO ELEMENTS FOUND")
            continue

        for element in elements:
            try :
                link = element.get_attribute("href")
            except NoSuchAttributeException as nsae:
                logging.exception(str(nsae) + " NO ATTRIBUTES FOUND")
                continue
            if "/watch" in link and link not in url_category:
                url_category.append(link)
                logging.info("Added " + link)
            else:
                continue

        random_url = random.choice(url_category)
        logging.info("Moving on to " + random_url)
        driver.get(random_url)
        time.sleep(2)

    for x in url_category:
        if len(url_list) <= iterations:
            url_list.append(x)
            logging.info(str(x) + " was added to the list")
        else:
            break

print("Succesfully scrapped " + str(iterations) + " number of URLs" )
logging.info("Succesfully scrapped " + str(iterations) + " number of URLs")

print("Outputting to CSV file now...")
logging.info("Outputting " + str(iterations) + " of URLs to CSV now...")

output_dir = os.path.join(args.savedir, 'scraped_urls_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))

df['url'] = url_list
df.to_csv(output_dir)
print("Successfully output to CSV file and closing chrome now")
logging.info("Successfully output to CSV file and closing chrome now")

driver.close()

















