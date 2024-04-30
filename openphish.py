import requests
from bs4 import BeautifulSoup
import pandas as pd
import schedule
import time
import json
from datetime import datetime
import os

def scrape_and_append():
    url = "https://openphish.com"
    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', class_='pure-table')
        urls = [row.find('td', class_='url_entry').text for row in table.find_all('tr')[1:]]
        unique_urls = list(set(urls))

        try:
            df = pd.read_csv('phishing_data.csv')
        except FileNotFoundError:
            df = pd.DataFrame(columns=['Phishing URL'])

        new_data = pd.DataFrame({'Phishing URL': unique_urls})
        num_new_urls = len(new_data)  # Number of new URLs added in this scrape
        df = pd.concat([df, new_data]).drop_duplicates().reset_index(drop=True)
        df.to_csv('phishing_data.csv', index=False)

        # Load or initialize log data
        log_data = {}
        if os.path.exists('logs.json'):
            with open('logs.json', 'r') as log_file:
                log_data = json.load(log_file)

        # Update log information
        log_data["scrapes_count"] = log_data.get("scrapes_count", 0) + 1
        log_data["last_scraping_datetime"] = str(datetime.now())
        log_data["new_urls_added"] = num_new_urls
        log_data["total_urls"] = len(df)

        with open('logs.json', 'w') as log_file:
            json.dump(log_data, log_file, indent=4)

        print("Data successfully scraped and appended to CSV.")

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")


def run():
    # schedule.every(120).minutes.do(scrape_and_append)  # Run every 5 minutes
    # while True:
    #     schedule.run_pending()
    #     time.sleep(1)

    scrape_and_append()
