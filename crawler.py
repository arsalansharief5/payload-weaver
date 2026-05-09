import time
from termcolor import colored
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

def crawl_website(zap, target_url):
    scan_id = zap.spider.scan(target_url)
    print("Crawling in progress...")
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(1)

    crawled_urls = sorted(set(zap.spider.results(scan_id)))

    if not crawled_urls:
        print(colored("No crawlable links were found on the website.", "red"))
    print(crawled_urls)
    return {
        "num_crawls": len(crawled_urls),
        "crawled_urls": crawled_urls,
    }

