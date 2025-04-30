import re
from urllib.parse import urlparse, urldefrag, urlunparse
from bs4 import BeautifulSoup
import hashlib

# Define all hashes in global scope in memory
all_hashes = []

# For report
unique_pages = set()
longest_page = {}
top_50_words = {}
sub_domains = {}

# Stop words
stop_words = []

def make_report():
    with open("report.txt", "a+") as file:
        file.write(f"Unique pages: {len(unique_pages)}")
        file.write(f"\nLongest Page: {longest_page}")
        file.write(f"\nTop 50 words:")
        sorted_word_freq = sorted(top_50_words.items(), key=lambda word: word[1], reverse=True)
        for word, freq in sorted_word_freq.items():
            file.write(f"{word}: {freq}")
        
        file.write(f"\n\nUnique pages:")
        for domain in sorted(sub_domains.keys()):
            file.write(f"{domain}: {sub_domains[domain]}")


def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    # Store all valid links here
    links = []

    # Detect and avoid dead URLs that return a 200 status but no data (click here to see what the different HTTP status codes mean
    if resp.status != 200 or resp.raw_response is None or resp.raw_response.url is None or resp.raw_response.content is None:
        return links
    
    # Detect and avoid crawling very large files, especially if they have low information value
    # 5 MB
    if len(resp.raw_response.content) > 5 * (2**20):
        return links
    
    # Parse content with lxml cause fastest, check if have href
    content = BeautifulSoup(resp.raw_response.content, "lxml")

    # Crawl all pages with high textual information content - just check if low info then return
    paragraphs = content.find_all("p")
    words = []
    for paragraph in paragraphs:
        words.append(paragraph.get_text(strip=True))
    all_paragraphs = " ".join(words)

    # Less than 50 words
    if len(all_paragraphs.split()) <= 50:
        return links
    
    # Detect and avoid sets of similar pages with no information
    #https://spotintelligence.com/2023/01/02/simhash/
    # simhash
    # Create/open hashes json

    # Get final hash of current content
    final_hash = simhash(content)

    # Check if current hash is similar to prev ones, if so return empty
    for prev_hashes in all_hashes:
        distance = compare_simhashes(final_hash, prev_hashes)
        if distance < 5:
            return links

    # Not similar to past ones, add to all_hashes
    all_hashes.append(final_hash)

    # All checks passed, defragment and return
    for link in content.find_all("a", href=True):
        original_url = link.get("href")

        # defragment it (it returns a tuple)
        link_defragged, dummy = urldefrag(original_url)
        links.append(link_defragged)

    # FOR REPORT
    all_text = get_clean_words(content)

    # Unique pages
    if link_defragged not in unique_pages:
        unique_pages.add(link_defragged)
    
    # Longest num of words
    text_length = len(all_text)
    if text_length > list(longest_page.values())[0]:
        longest_page.clear()
        longest_page[url] = text_length
    
    # 50 most common words
    for word in all_text:
        lower_word = word.lower()
        if lower_word not in stop_words:
            top_50_words[word] = 1 + top_50_words.get(word, 0)
    
    # Subdomains
    parsed = urlparse(url)
    if parsed.hostname and parsed.hostname.endswith("uci.edu") and parsed.hostname != "uci.edu":
        sub_domains[parsed.hostname] = 1 + sub_domains.get(parsed.hostname, 0)

    return links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.

    # All url/path that we have to verify
    valid_url = [
        "ics.uci.edu",
        "cs.uci.edu",
        "informatics.uci.edu",
        "stat.uci.edu",
    ]
    valid_url_path = "today.uci.edu/department/information_computer_sciences/"


    try:
        parsed = urlparse(url)
        original_url_no_scheme = urlunparse(("", parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
        if original_url_no_scheme.startswith("//"):
            original_url_no_scheme = original_url_no_scheme[2:]

        # Check bad extension type
        bad_extension_type = re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz|xml)$", parsed.path.lower())
        
        if bad_extension_type:
            return False

        # Check is not correct scheme http/https
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        # Detect and avoid infinite traps
        #https://www.conductor.com/academy/crawler-traps/
        traps = ["calendar", "year=", "month=", "day=", "date=", "page=", "sort=", "id=", 
                 "page=", "p=", "page_id=", "pageid=", "search", "filter=", "filter", "limit=", "limit", "order=",
                 "replytocom=", "reply=", "archive", "archives", "past", "old",
                 "year", "month", "day", "date", "page", "sort", "id", "p", "page_id"]
        path_words = [word for word in (parsed.path).split("/") if word]
        query_words = (re.sub(r"[^A-Za-z]", " ", parsed.query)).split()
        all_path_query_words = set(path_words + query_words)
        bad_traps_bool = all_path_query_words & set(traps)

        if bad_traps_bool:
            return False

        # DO EVERYTHING RETURNING TO FALSE BEFORE CHECKING FOR TRUE
        if parsed.hostname:
            for url in valid_url:
                if parsed.hostname.endswith(url) or original_url_no_scheme.startswith(valid_url_path):
                    return True

        return False

    except TypeError:
        print ("TypeError for ", parsed)
        raise


def get_word_freq(all_clean_words):
    word_freq = {}
    for word in all_clean_words:
        word_freq[word] = 1 + word_freq.get(word, 0)
    return word_freq


def get_clean_words(content):
    all_text = content.get_text(separator=" ", strip=True).split()
    all_clean_words = []

    for word in all_text:
        clean_word = re.sub(r"[^A-Za-z0-9]", "", word)
        if clean_word:
            all_clean_words.append(clean_word)

    return all_clean_words

def simhash(content):
    all_clean_words = get_clean_words(content)
    word_freq = get_word_freq(all_clean_words)
    
    all_hashes = []
    for word, freq in word_freq.items():
        for dummy in range(freq):
            hashed = hashlib.sha1(word.encode("utf-8")).hexdigest()
            all_hashes.append(hashed)

    combined_hash = "".join(all_hashes)
    final_hash = hashlib.sha1(combined_hash.encode("utf-8")).hexdigest()
    return final_hash


def compare_simhashes(simhash1, simhash2):
    int_simhash1 = int(simhash1, 16)
    int_simhash2 = int(simhash2, 16)

    distance = bin(int_simhash1 ^ int_simhash2).count('1')

    return distance

# when all checks good/call in extractnextlinks,

# unique pages: just store all in array, if new url not in array, add it
# - use len(unique_pages) when making report

# longest num of words not including html markup, use get_text() beutifl soup
# - store this url/num in a dict, if > then change

# 50 most common words not including english stop words that are sorted by frequency
# - use all_clean_words = get_clean_words(content), word_freq = get_word_freq(all_clean_words)
# - instaed of get_word_freq, make new function using the global dict
# - if not in english stop words add to dict
# - sort in make_report, like in A1

# Subdomains in uci.edu (ex: https://cs.ics.uci.edu/)
# - like in word_freq
# - get hostname
# - if hostname=TRUE and hostname ends with uci.edu, do the get thing leetcode with 1 + get on dict
# - in make_report sort alphabetically

# in worker when make_report is called and info is returned (4 things)
# - make 4 different txt files containng them

# CALL MAKE REPORT IN WORKER WHEN FRONTIER DONE
