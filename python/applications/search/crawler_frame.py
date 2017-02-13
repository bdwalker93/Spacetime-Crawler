import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager, invalidlinks
from spacetime_local.IApplication import IApplication
from spacetime_local.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os, sys
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
DEBUG_VERY_VERBOSE = False

visited_subdomains = {}
most_outlinks = ("None", 0)
#Absolute path to location of analytics_data.txt
fpath_analytics_data = os.path.join(sys.path[0], "analytics_data.txt")
#Absolute path to location of analytics.txt
fpath_finalAnalytics = os.path.join(sys.path[0], "analytics.txt")

#Will update analytics_data.txt
def updateAnalyticsFile():
    with open(fpath_analytics_data, "w") as f:
        f.write(str(invalidlinks) + "\n")
        f.write(most_outlinks[0] + " " + str(most_outlinks[1]) + "\n")
        for subdomain, urls in visited_subdomains.items():
            f.write(subdomain)
            for url in urls:
                f.write(" " + url)
            f.write("\n")


#If successfull_url count is 0 then we intialize analytics_data.txt with empty values
if len(url_count) == 0:
    updateAnalyticsFile()
else: #Else read in the saved analytics data
    try:
        with open(fpath_analytics_data, "r") as f:
            invalidlinks = int(f.readline().rstrip())

            line = f.readline().rstrip().split()
            most_outlinks = (line[0], int(line[1]))

            for line in f:
                split_line = line.rstrip().split()
                subdomain = split_line[0]
                urls = set(split_line[1:])
                visited_subdomains[subdomain] = urls
    except Exception:
        print("Need to ensure on first run that \"succesfull_url.txt\" is empty to initialize analytics with fresh file")




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
        with open(fpath_finalAnalytics, 'w') as f:

            #Writes to file all subdomains and the count for unique URL extracted
            f.write("All subdomains visited and a count for every unique URL extracted\n")
            for subdomain, urls in visited_subdomains.items():
                f.write("\t" + str(subdomain) + ": " + str(len(urls)) + "\n")

            #Writes to file the number of invalid links the crawler has recieved
            f.write("\nInvalid links received: " + str(invalidlinks) + "\n")

            #Writes to file the page with most outlinks extracted
            f.write("\n" + str(most_outlinks[0]) + " is page with most outlinks of " + str(most_outlinks[1]) + "\n")

        print "downloaded ", len(url_count), " in ", time() - self.starttime, " seconds."
        pass

def save_count(urls):
    global url_count
    urls = set(urls).difference(url_count)
    url_count.update(urls)
    if len(urls):
        with open("successful_urls.txt", "a") as surls:
            surls.write(("\n".join(urls) + "\n").encode("utf-8"))


def process_url_group(group, useragentstr):
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)

    save_count(successfull_urls)
    updateAnalyticsFile()

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
            if DEBUG_VERY_VERBOSE:
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
                    visited_subdomains[hostName].add(absoluteUrl)



                #If outlinks is currently empty then assign it new tuple
                if most_outlinks[0] == "None":
                    most_outlinks = (basePath, len(outlinks))
                #If the current tuples outlinks count is lower to current then replace
                elif most_outlinks[1] < len(outlinks):
                    most_outlinks = (basePath, len(outlinks))

                outputLinks += outlinks

            except AssertionError as err:
                # Setting this as a bad link
                urlResponse.bad_url = True

                # might want to set that built in bad within the url object here???
                if DEBUG:
                    print err.message
        else:
            # Setting this as a bad link
            urlResponse.bad_url = True
            if DEBUG:
                print "No content or an error code exists"
    # Debug
    if DEBUG_VERBOSE:
        print "List of found link: ", outputLinks

    return outputLinks

def is_valid(url):
    global invalidlinks

    bad_subdomains = ["graphmod", "grape", "ganglia"]

    # Parses URL
    parsed = urlparse(url)

    # Sets up parse search
    parsedQuerySearch = parse_qs(parsed.query)

    #Gets the host name
    hostName = parsed.hostname

    # Gets the path of the URL
    path = parsed.path

    if parsed.scheme not in set(["http", "https"]):
        invalidlinks += 1
        return False

    #If the hostname contains any of the known bad subdomains then we ignore
    for subdomain in bad_subdomains:
        if subdomain in hostName:
            invalidlinks += 1
            if DEBUG:
                print("Blocking: ", hostName)
            return False

    # Trying to handle the dynamic PHP from the UCI calender (but dont want to block the events)
    if "calendar" in hostName:
        if "month" in parsedQuerySearch or "day" in parsedQuerySearch or "year" in parsedQuerySearch:
            if DEBUG:
                print "Blocking:", url
            return False


    # Ignore anything with broken link tags left in the URL
    if "<a>" in parsedQuerySearch or "<\a>" in parsedQuerySearch:
        invalidlinks += 1
        return False

    # https://cbcl.ics.uci.edu/doku.php/start?do=login&sectok=6e0060616499c91512fcb5b63d90f778
    # Keeps getting called with different tokens (nothing really there to crawl anyways)
    if "cbcl" in hostName:
        if "do" in parsedQuerySearch and "login" in parsedQuerySearch["do"]:
            invalidlinks += 1
            if DEBUG:
                print "Blocking:", hostName
            return False

    # https://duttgroup.ics.uci.edu/doku.php/drg101_admin?image=farewell.jpg&tab_details=view&do=media&tab_files=files&ns=presentations%3Aseminar
    # Keeps coming up and we dont seem to have access to almost anything with media
    if "duttgroup" in hostName:
        if "do" in parsedQuerySearch and "media" in parsedQuerySearch["do"]:
            invalidlinks += 1
            if DEBUG:
                print "Blocking:", hostName
            return False

    # http://archive.ics.uci.edu/ml/datasets.html?format=nonmat&task=&att=mix&area=game&numAtt=greater100&numIns=100to1000&type=other&sort=dateUp&view=table
    # Edward Xia recommendation
    if "archive" in hostName and "datasets.html" in path:
        if parsedQuerySearch:
            invalidlinks += 1
            if DEBUG:
                print "Blocking:", hostName
            return False

    #Possibly need to count this as a sign of invalid link

    # Another Edward Xia recommendation
    try:
        if not re.search("\.ics\.uci\.edu\.?$", parsed.hostname) \
            or re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
            invalidlinks += 1
            if DEBUG_VERY_VERBOSE:
                print "ZZZZZ"
                print "Blocking (File Types):", hostName
                print "url: ", url
                print "parsed: ", hostName, "***", not re.search("\.ics\.uci\.edu\.?$", parsed.hostname)
                print "------"
            return False

    except TypeError:
        print ("TypeError for ", parsed)
        return False



    # If nothing fails it must be true
    return True
