import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager
from spacetime_local.IApplication import IApplication
from spacetime_local.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os
from time import time
import StringIO

try:
    # For python 2
    from urlparse import urlparse, parse_qs, urljoin
except ImportError:
    # For python 3
    from urllib.parse import urlparse, parse_qs,  urljoin


logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = (set() 
    if not os.path.exists("successful_urls.txt") else 
    set([line.strip() for line in open("successful_urls.txt").readlines() if line.strip() != ""]))
MAX_LINKS_TO_DOWNLOAD = 3000
DEBUG = True
DEBUG_VERBOSE = False

#Read in the listed subdomains from bad_subdomains.txt
bad_subdomains = ["graphmod.ics.uci.edu", "grape.ics.uci.edu", "ganglia.ics.uci.edu", "calendar.ics.uci.edu"]
visited_subdomains = {}
most_outlinks = (None, None)
download_times = []
invalidlinks = 0

@Producer(ProducedLink)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "75806831_23663450_31646543"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR W17 Undergrad 75806831, 23663450, 31646543"
		
        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        for g in self.frame.get(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks, urlResps = process_url_group(g, self.UserAgentString)
            for urlResp in urlResps:
                if urlResp.bad_url and self.UserAgentString not in set(urlResp.dataframe_obj.bad_url):
                    urlResp.dataframe_obj.bad_url += [self.UserAgentString]
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)

        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        with open("analytics.txt", 'w') as f:

            #Writes to file all subdomains and the count for unique URL extracted
            f.write("All subdomains visited and a count for every unique URL extracted\n")
            for subdomain, urls in visited_subdomains:
                f.write("\t" + str(subdomain) + ": " + len(urls) + "\n")

            #Writes to file the number of invalid links the crawler has recieved
            f.write("\nInvalid links received: " + str(invalidlinks) + "\n")

            #Writes to file the page with most outlinks extracted
            f.write("\n" + str(most_outlinks[0]) + " is page with most outlinks of " + str(most_outlinks[1]) + "\n")

            #Writes to file the average download time per URL
            f.write("\nAverage download time per URL: " + str(sum(download_times)/len(download_times)))


        print "downloaded ", url_count, " in ", time() - self.starttime, " seconds."
        pass

def save_count(urls):
    global url_count
    url_count.update(set(urls))
    with open("successful_urls.txt", "a") as surls:
        surls.write(("\n".join(urls) + "\n").encode("utf-8"))


def process_url_group(group, useragentstr):
    #Assuming this is where the download per URL is occuring
    global download_times
    start = time()
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    end = time()
    download_times.append(end-start)

    save_count(successfull_urls)

    # Debug
    if DEBUG:
        print "This is the url count: ", len(url_count)

    return extract_next_links(rawDatas), rawDatas
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    global most_outlinks, visited_subdomains
    outputLinks = list()

    for urlResponse in rawDatas:
        outlinks = []


        # The URL base path
        basePath = urlResponse.url

        hostName = urlparse(basePath).hostname
        if hostName not in visited_subdomains:
            visited_subdomains[hostName] = set()


        # The content of the page
        content = urlResponse.content

        # Stops us from trying parse pages with no content or an error
        if not urlResponse.error_message or content:

            # Debug
            if DEBUG_VERBOSE:
                print "Error Message: ", urlResponse.error_message
                print "Headers: ", urlResponse.headers
                print "Is Redirected: ", urlResponse.is_redirected
                print "Final URL: ", urlResponse.final_url
                print "Content: ", urlResponse.content, "-\n"
                print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

            try:
                # Loading the DOM with etree
                parser = etree.HTMLParser(recover=True)
                pageDom = etree.parse(StringIO.StringIO(content), parser)

                # Checks for the presence of a base tag
                if pageDom.xpath('//base/@href'):
                    basePath = pageDom.xpath('//base/@href')[0]

                # Extracting all of the links
                for linkPath in pageDom.xpath('//a/@href'):

                    # absolutePath = urljoin(basePath, relativePath)
                    absoluteUrl = urljoin(basePath, linkPath)

                    # Adding link to list
                    outlinks.append(absoluteUrl)
                    hostName[hostName].add(absoluteUrl)



                #If outlinks is currently empty then assign it new tuple
                if most_outlinks[0] == None:
                    most_outlinks = (basePath, len(outlinks))
                #If the current tuples outlinks count is lower to current then replace
                elif most_outlinks[1] < len(outlinks):
                    most_outlinks = (basePath, len(outlinks))

                outputLinks += outlinks

            except AssertionError as err:
                # might want to set that built in bad within the url object here???
                if DEBUG:
                    print err.message
        else:
            #might want to set that built in bad within the url object here???
            if DEBUG:
                print "No content or an error code exists"
    # Debug
    if DEBUG_VERBOSE:
        print "List of found link: ", outputLinks

    '''
    rawDatas is a list of objs -> [raw_content_obj1, raw_content_obj2, ....]
    Each obj is of type UrlResponse  declared at L28-42 datamodel/search/datamodel.py
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml
    '''
    return outputLinks

def is_valid(url):
    global invalidlinks, bad_subdomains

    # Parses URL
    parsed = urlparse(url)

    # Sets up parse search
    parsedQuerySearch = parse_qs(parsed.query)

    #Gets the host name
    hostName = parsed.hostname

    if parsed.scheme not in set(["http", "https"]):
        invalidlinks += 1
        return False

    # Ignore anything with broken link tags left in the URL
    if "<a>" or "<\a>" in parsedQuerySearch:
        invalidlinks += 1
        return False

    #If the hostname contains any of the known bad subdomains then we ignore
    for subdomain in bad_subdomains:
        if subdomain in hostName:
            invalidlinks += 1
            if DEBUG:
                print("Blocking: ", hostName)
            return False

    # https://cbcl.ics.uci.edu/doku.php/start?do=login&sectok=6e0060616499c91512fcb5b63d90f778
    # Keeps getting called with different tokens (nothing really there to crawl anyways)
    if "cbcl" in hostName:
        if "login" in parsedQuerySearch:
            invalidlinks += 1
            if DEBUG:
                print "Blocking:", hostName
            return False


    #Possibly need to count this as a sign of invalid link
    try:
        return ".ics.uci.edu" in parsed.hostname \
            and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)


