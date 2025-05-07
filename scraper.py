import re
from urllib.parse import urlparse, urldefrag, urlunparse, parse_qs
from bs4 import BeautifulSoup
import hashlib
import json
import os
from collections import Counter

SAVE_FILE = "saved_vars.json"
HASHES_FILE = "all_hashes.json"

# Stop words
stop_words = ['a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', "aren't", 'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by', "can't", 'cannot', 'could', "couldn't", 'did', "didn't", 'do', 'does', "doesn't", 'doing', "don't", 'down', 'during', 'each', 'few', 'for', 'from', 'further', 'had', "hadn't", 'has', "hasn't", 'have', "haven't", 'having', 'he', "he'd", "he'll", "he's", 'her', 'here', "here's", 'hers', 'herself', 'him', 'himself', 'his', 'how', "how's", 'i', "i'd", "i'll", "i'm", "i've", 'if', 'in', 'into', 'is', "isn't", 'it', "it's", 'its', 'itself', "let's", 'me', 'more', 'most', "mustn't", 'my', 
'myself', 'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same', "shan't", 'she', "she'd", "she'll", "she's", 'should', "shouldn't", 'so', 'some', 
'such', 'than', 'that', "that's", 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', "there's", 'these', 'they', "they'd", "they'll", "they're", "they've", 'this', 'those', 'through', 'to', 'too', 'under', 'until', 
'up', 'very', 'was', "wasn't", 'we', "we'd", "we'll", "we're", "we've", 'were', "weren't", 'what', "what's", 'when', "when's", 'where', "where's", 'which', 'while', 'who', "who's", 'whom', 'why', "why's", 'with', "won't", 'would', "wouldn't", 'you', "you'd", "you'll", "you're", "you've", 'your', 'yours', 'yourself', 'yourselves']

# Load json save file
if os.path.exists(SAVE_FILE):
    with open(SAVE_FILE, "r") as file:
        json_file = json.load(file)
        unique_pages = set(json_file["unique_pages"])
        longest_page = json_file["longest_page"]
        top_50_words = json_file["top_50_words"]
        sub_domains = json_file["sub_domains"]
else:
    unique_pages = set()
    longest_page = {}
    top_50_words = {}
    sub_domains = {}

# Load json hash file
if os.path.exists(HASHES_FILE):
    with open(HASHES_FILE, "r") as file:
        all_hashes = json.load(file)
else:
    all_hashes = {}


# Save json save
def save_json_save_file():
    with open(SAVE_FILE, "w") as file:
        json.dump({
            "unique_pages": list(unique_pages),
            "longest_page": longest_page,
            "top_50_words": top_50_words,
            "sub_domains": sub_domains
        }, file, indent=4)


# Save json hash
def save_json_hash_file():
    with open("all_hashes.json", "w") as file:
        json.dump(all_hashes, file, indent=4)


def make_report():
    with open("saved_vars.json", "r") as f:
        state = json.load(f)
        unique_pages = set(state["unique_pages"])
        longest_page = state["longest_page"]
        top_50_words = state["top_50_words"]
        sub_domains = state["sub_domains"]

    with open("report.txt", "w") as file:
        file.write(f"Unique pages: {len(unique_pages)}")

        file.write(f"\n\nLongest Page:\n")
        for url, count in longest_page.items():
            file.write(f"{url} - {count} words\n")

        file.write(f"\nTop 50 words:\n")
        sorted_word_freq = sorted(top_50_words.items(), key=lambda word: word[1], reverse=True)[:50]
        for word, freq in sorted_word_freq:
            file.write(f"{word} - {freq}\n")

        file.write(f"\nSubdomains {len(sub_domains)}:\n")
        for domain in sorted(sub_domains):
            file.write(f"{domain} - {sub_domains[domain]}\n")


def scraper(url, resp):
    links = extract_next_links(url, resp)

    valid_links = []
    for link in links:
        if is_valid_domain(link):
            # Unique pages
            if link not in unique_pages:
                unique_pages.add(link)

            # Subdomains
            parsed = urlparse(link)
            if parsed.netloc and parsed.netloc.endswith("uci.edu") and parsed.netloc != "uci.edu" and "@" not in parsed.netloc:
                sub_domains[parsed.netloc] = 1 + sub_domains.get(parsed.netloc, 0)

        if is_valid(link):
            valid_links.append(link)
    
    save_json_save_file()
    save_json_hash_file()

    return valid_links


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

    # Less than 35 words
    if len(all_paragraphs.split()) <= 30:
        return links
    
    # Detect and avoid sets of similar pages with no information
    #https://spotintelligence.com/2023/01/02/simhash/
    # simhash

    # Get final hash of current content
    final_hash = simhash(content)

    # Check if current hash is similar to prev ones, if so return empty
    for prev_hashes in all_hashes.values():
        distance = compare_simhashes(final_hash, prev_hashes)
        if distance < 3:
            return links

    # Not similar to past ones, add to prev hashes json
    all_hashes[url] = final_hash

    # FOR REPORT
    all_text = get_clean_words(content)

    # All checks passed, defragment and return
    for link in content.find_all("a", href=True):
        original_url = link.get("href")

        # defragment it (it returns a tuple)
        link_defragged, _ = urldefrag(original_url)
        links.append(link_defragged)

    # Longest num of words not html markup
    text_length = len(all_text)
    if longest_page and text_length > list(longest_page.values())[0]:
        longest_page.clear()
        longest_page[url] = text_length
    elif not longest_page:
        longest_page[url] = text_length

    # 50 most common words
    for word in all_text:
        if not word.isdigit():
            lower_word = word.lower()
            if lower_word not in stop_words:
                top_50_words[lower_word] = 1 + top_50_words.get(lower_word, 0)

    return links


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.

    try:
        parsed = urlparse(url)

        # Check bad extension type
        bad_extension_type = re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz|xml|apk|war|img|sql|ppsx)$", parsed.path.lower())
        
        if bad_extension_type:
            return False

        # Check is not correct scheme http/https
        if parsed.scheme not in set(["http", "https"]):
            return False

        # Detect and avoid infinite traps
        #https://www.conductor.com/academy/crawler-traps/
        traps = ["calendar", "year=", "month=", "day=", "date=",
                "year", "month", "day", "date",
                "week", "week=", "page", "pages", "page_id", "pageid",
                "tribe", "custom", "doku.php",
                "replytocom=", "reply=", "mailto=", "mailto:",
                "ical", "eventdate", "eventdisplay", "post_type", "tribe-bar-date"]

        path_words = [word.lower() for word in (parsed.path).split("/") if word]
        if set(traps).intersection(path_words):
            return False
        
        query_words = set(key.lower() for key in parse_qs(parsed.query).keys())
        if set(traps).intersection(query_words):
            return False
        
        # FOR DATES AKA THE ICS CALENDAR, gets 4digit-2digit-optional 2digit, if any path matches, false
        query_words_vals = parse_qs(parsed.query).values()
        date = re.compile(r"\d{4}-\d{2}(-\d{2})?")
        if any(date.fullmatch(word) for word in path_words):
            return False
        if any(date.fullmatch(word[0]) for word in query_words_vals):
            return False

        # Check if valid domain
        return is_valid_domain(url)

    except TypeError:
        print ("TypeError for ", parsed)
        raise


# Get frequency of words
def get_word_freq(all_clean_words):
    return Counter(all_clean_words)


# Get clean words ascii
def get_clean_words(content):
    all_text = content.get_text(separator=" ", strip=True).split()
    all_clean_words = []

    for word in all_text:
        clean_word = re.sub(r"[^A-Za-z0-9]", "", word)
        if clean_word:
            all_clean_words.append(clean_word)

    return all_clean_words


# Simhash and save
def simhash(content):
    all_clean_words = get_clean_words(content)
    word_freq = get_word_freq(all_clean_words)
    
    all_hashes = []
    for word, freq in word_freq.items():
        for _ in range(freq):
            hashed = hashlib.sha1(word.encode("utf-8")).hexdigest()
            all_hashes.append(hashed)

    combined_hash = "".join(all_hashes)
    final_hash = hashlib.sha1(combined_hash.encode("utf-8")).hexdigest()
    return final_hash


# Compare simhashes
def compare_simhashes(simhash1, simhash2):
    int_simhash1 = int(simhash1, 16)
    int_simhash2 = int(simhash2, 16)

    distance = bin(int_simhash1 ^ int_simhash2).count('1')

    return distance


def is_valid_domain(url):
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

        if parsed.netloc:
            for url in valid_url:
                if parsed.netloc.lower().endswith(url) or original_url_no_scheme.lower().startswith(valid_url_path):
                    return True
        return False

    except TypeError:
        print ("TypeError for ", parsed)
        raise

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
