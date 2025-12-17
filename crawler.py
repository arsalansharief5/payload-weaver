import time
from termcolor import colored
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

def crawl_website(zap, target_url):
    zap.spider.scan(target_url)
    print("Crawling in progress...")
    while int(zap.spider.status()) < 100:
        time.sleep(1)
     
    crawled_urls = zap.spider.results()
    
    if not crawled_urls:
        print(colored("No crawlable links were found on the website.", "red"))
    print(crawled_urls)
    return {
        "num_crawls": len(crawled_urls),
        "crawled_urls": crawled_urls,
    }

