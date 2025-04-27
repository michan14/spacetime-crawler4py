from threading import Thread

from inspect import getsource
from utils.download import download
from utils import get_logger
from urllib.parse import urlparse
import scraper
import time


class Worker(Thread):
    def __init__(self, worker_id, config, frontier):
        # Save time accessed to domains
        domains_with_times = {}

        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            tbd_url = self.frontier.get_tbd_url()
            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                break
            
            # Honor the politeness delay for each site, just using time.sleep with politeness delay in config
            domain = urlparse(tbd_url).netloc

            if domain in self.domains_with_times:
                prev_time = self.domains_with_times[domain]
                last_accessed_time = time.time() - prev_time

                if last_accessed_time < self.config.time_delay:
                    time.sleep(self.config.time_delay - last_accessed_time)

            resp = download(tbd_url, self.config, self.logger)
            self.logger.info(
                f"Downloaded {tbd_url}, status <{resp.status}>, "
                f"using cache {self.config.cache_server}.")
            scraped_urls = scraper.scraper(tbd_url, resp)
            for scraped_url in scraped_urls:
                self.frontier.add_url(scraped_url)
            self.frontier.mark_url_complete(tbd_url)
            # Re add the prev time domain was accessed
            self.domains_with_times[domain] = time.time()
            time.sleep(self.config.time_delay)
