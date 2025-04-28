import re
import requests
from urllib.parse import urlparse, urldefrag, urlunparse
from bs4 import BeautifulSoup
import hashlib
import json

# def scraper(url, resp):
#     links = extract_next_links(url, resp)
#     return [link for link in links if is_valid(link)]

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



    # EVERYTHING GIVEN IN THIS FUNCTION IS ALREADY VALID CAUSE ITS FROM THE FRONTIER
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
    try:
        with open("all_hashes.json", "r") as file:
            all_hashes = json.load(file)
    except FileNotFoundError:
        all_hashes = {}
        with open("all_hashes.json", "w") as file:
            json.dump(all_hashes, file, indent=4)
    
    # Get final hash of current content
    final_hash = simhash(content)

    # Load all prev hashes
    with open("all_hashes.json", "r") as file:
        all_hashes = json.load(file)

    # Check if current hash is similar to prev ones, if so return empty
    for prev_hashes in all_hashes.values():
        distance = compare_simhashes(final_hash, prev_hashes)
        if distance < 5:
            return links

    # Not similar to past ones, add to prev hashes json
    all_hashes[url] = final_hash
    with open("all_hashes.json", "w") as file:
        json.dump(all_hashes, file, indent=4)

    # All checks passed, defragment and return
    for link in content.find_all("a", href=True):
        original_url = link.get("href")

        # defragment it (it returns a tuple)
        link_defragged, dummy = urldefrag(original_url)
        links.append(link_defragged)

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
                 "replytocom=", "reply=", "archive", "archives", "past", "old"]
        for trap in traps:
            if trap in parsed.path or trap in parsed.query:
                return False

        # DO EVERYTHING RETURNING TO FALSE BEFORE CHECKING FOR TRUE
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


if __name__ == "__main__":
    html_doc = """
    <html><head><title>The Dormouse's story</title></head>
    <body>
    <p class="title"><b>The Dormouse's story</b></p>

    <p class="story">Once upon a time there were three little sisters; and their names were
    <a href="http://example.com/elsie#bruh" class="sister" id="link1">Elsie</a>,
    <a href="https://ics.uci.edu/facts-figures/ics-mission-history/" class="sister" id="link2">Lacie</a> and
    <a href="https://cs.ics.uci.edu/" class="sister" id="link3">Tillie</a>;
    <a href="https://tutoring.ics.uci.edu/resources/" class="sister" id="link3">Tillie</a>;
    <a href="https://today.uci.edu/department/information_computer_sciences/" class="sister" id="link3">Tillie</a>;
    <a href="https://ics.uci.edu/~wjohnson/BIDA/Ch8/prioriterates.txt" class="sisterdafdsafdsa" id="link3">Tilliefdsafdsa</a>;
    <a href="http://docs.python.org:80/3/library/urllib.parse.html?highlight=params#url-parsing" class="sister" id="link1">Elsie</a>,
    and they lived at the bottom of a well.</p>

    <p class="story">Generating random paragraphs can be an excellent way for writers to get their creative flow going at the beginning of the day. The writer has no idea what topic the random paragraph will be about when it appears. This forces the writer to use creativity to complete one of three common writing challenges. The writer can use the paragraph as the first one of a short story and build upon it. A second option is to use the random paragraph somewhere in a short story they create. The third option is to have the random paragraph be the ending paragraph in a short story. No matter which of these challenges is undertaken, the writer is forced to use creativity to incorporate the paragraph into their writing. </p>
    """

    html_doc2 = """
    <html><head><title>The Dormouse's story</title></head>
    <body>
    <p class="title"><b>The Dormouse's story</b></p>

    <p class="story">Once upon a time there were three little sisters; and their names were
    <a href="http://example.com/elsie#bruh" class="sister" id="link1">Elsie</a>,
    <a href="https://ics.uci.edu/facts-figures/ics-mission-history/" class="sister" id="link2">Lacie</a> and
    <a href="https://cs.ics.uci.edu/" class="sister" id="link3">Tillie</a>;
    <a href="https://tutoring.ics.uci.edu/resources/" class="sister" id="link3">Tillie</a>;
    <a href="https://today.uci.edu/department/information_computer_sciences/" class="sister" id="link3">Tillie</a>;
    <a href="https://ics.uci.edu/~wjohnson/BIDA/Ch8/prioriterates.txt" class="sisterdafdsafdsa" id="link3">Tilliefdsafdsa</a>;
    <a href="http://docs.python.org:80/3/library/urllib.parse.html?highlight=params#url-parsing" class="sister" id="link1">Elsie</a>,
    and they lived at the bottom of a well.</p>

    <p class="story">Generating random paragraphs can be an excellent way for writers to get their creative flow going at the beginning of the day. The writer has no idea what topic the random paragraph will be about when it appears. This forces the writer to use creativity to complete one of three common writing challenges. The writer can use the paragraph as the first one of a short story and build upon it. A second option is to use the random paragraph somewhere in a short story they create. The third option is to have the random paragraph be the ending paragraph in a short story. No matter which of these challenges is undertaken, the writer is forced to use creativity to incorporate the paragraph into their writing. </p>
    """

    class FakeResp:
        def __init__(self, content):
            self.status = 200
            self.raw_response = self
            self.url = "http://test.com"
            self.content = content.encode("utf-8")

    resp = FakeResp(html_doc)
    resp2 = FakeResp(html_doc2)
    links = extract_next_links("http://test.com", resp)
    links2 = extract_next_links("http://test.com", resp2)



    valids = [link for link in links if is_valid(link)]
    for l in valids:
        print(l)

    valids2 = [link for link in links2 if is_valid(link)]
    for l in valids2:
        print(l)