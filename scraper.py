import re
import requests
from urllib.parse import urlparse, urldefrag, urlunparse
from bs4 import BeautifulSoup

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


    # All url/path that we have to verify
    valid_url = [
        "ics.uci.edu",
        "cs.uci.edu",
        "informatics.uci.edu",
        "stat.uci.edu",
    ]
    valid_url_path = "today.uci.edu/department/information_computer_sciences/"

    # Store all valid links here
    links = []

    # Parse content with lxml cause fastest, check if have href, parse hostname, parse for no scheme
    content = BeautifulSoup(resp, "lxml")
    for link in content.find_all("a", href=True):
        original_url = link.get("href")
        parsed_url = urlparse(original_url)
        original_url_no_scheme = urlunparse(("", parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))
        if original_url_no_scheme.startswith("//"):
            original_url_no_scheme = original_url_no_scheme[2:]

        # if valid with links, defragment it (it returns a tuple)
        if parsed_url.hostname:
            for url in valid_url:
                if parsed_url.hostname.endswith(url) or original_url_no_scheme.startswith(valid_url_path):
                    link_defragged, dummy = urldefrag(original_url)
                    links.append(link_defragged)
                    break

    return links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise


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
    <a href="https://cs.ics.uci.edu/" class="sisterdafdsafdsa" id="link3">Tilliefdsafdsa</a>;
    and they lived at the bottom of a well.</p>

    <p class="story">...</p>
    """
    links = extract_next_links("test", html_doc) # PRETEND THAT RESP = THE EXAMPLE HTML DOC, CHANGE IT BACK WHENEVBER WITH RESP.CONTENT STUFFS

    # TODO EXTRACTNEXTLINKS
    # Detect and avoid dead URLs that return a 200 status but no data (click here to see what the different HTTP status codes mean
    # Crawl all pages with high textual information content (CHECK IF CONTENT GOOD, IF GOOD THEN PARSE AND GET LINKS)
    # Detect and avoid crawling very large files, especially if they have low information value (SAME AS ABOVE IF LOW INFO VALUE/LARGE SIZE DONT BOTHER)
    # Detect and avoid sets of similar pages with no information
    # Honor the politeness delay for each site

    # TODO ISVALID
    # Detect and avoid infinite traps


    valids = [link for link in links if is_valid(link)]
    for l in valids:
        print(l)