# jspector.py

import time
import re
import glob
import jsbeautifier
import requests
import string
import random
import argparse
import os
import sys
import signal
from html import escape
from urllib.parse import urlparse
from lxml import html
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.service import Service as EdgeService
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from selenium.common.exceptions import WebDriverException, SessionNotCreatedException, NoSuchWindowException

# disable warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def signal_handler(sig, frame):
    print("\nCtrl+C pressed. Exiting...")
    sys.exit(0)
    
signal.signal(signal.SIGINT, signal_handler)

# Colors
RESET = '\033[0m'
WHITE = '\033[1;37m'
BLUE = '\033[1;34m'
MAGENTA = '\033[1;35m'
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[1;36m'

_regex = {
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    'email_id' : r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    'credit_card_number' : r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})(?:[0-9]{3,4})?\b',
    'social_security_number' : r'\b\d{3}-\d{2}-\d{4}\b',
    'phone_number' : r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    'ip_address' : r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    'pan_number' : r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$',
    'aadhar_number' : r'^\d{12}$',
    'voter_id' : r'^[A-Z]{3}[0-9]{7}$',
    'bank_account_number' : r'^[0-9]{9,18}$',
    'ifsc_code' : r'^[A-Z]{4}[0-9]{7}$',
    'swift_code' : r'^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$',
    'passport_number' : r'^[A-Z]{1,2}[0-9]{7}$',
    'driving_license_number' : r'^[A-Z]{2}[0-9]{13}$',
    'ration_card_number' : r'^[A-Z]{1,2}[0-9]{7}$',
    'employee_id' : r'^[A-Z]{2,3}[0-9]{4,6}$',
    'student_id' : r'^[A-Z]{2,3}[0-9]{4,6}$',
    'taxpayer_identification_number' : r'^[A-Z]{1,2}[0-9]{7}$',
    'national_insurance_number' : r'^[A-Z]{2}[0-9]{6}[A-Z]$',
    'state_id' : r'^[A-Z]{2}[0-9]{7}$',
    'military_id' : r'^[A-Z]{1,2}[0-9]{7}$',
}

def print_banner():
    print(f"{CYAN}█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
    print(f"{CYAN}█                      » JSpector «                       █")
    print(f"{CYAN}█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█{RESET}")
    print("")
    print(f"{CYAN}                                              - By Vigrahak{RESET}")
    print(f"{RED}Have a beer :  {CYAN}https://www.paypal.com/paypalme/SourabhS1828")
    print("")

def getContext(matches, content, name, rex='.*'):
    ''' get context '''
    items = []
    matches2 = []
    for i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        escaped_rex = re.escape(rex)
        escaped_m = re.escape(m)
        context = re.findall(r'%s(.{0,100})%s' % (escaped_rex, escaped_m), content, re.IGNORECASE | re.DOTALL)

        item = {
            'matched': m,
            'name': name,
            'context': context,
            'multi_context': True if len(context) > 1 else False
        }
        items.append(item)
    return items

def parser_file(content, mode=1, more_regex=None, no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";", ";\r\n").replace(",", ",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1], re.VERBOSE | re.I)
        if mode == 1:
            all_matches = [(m.group(0), m.start(0), m.end(0)) for m in re.finditer(r, content)]
            items = getContext(all_matches, content, regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{
                'matched': m.group(0),
                'context': [],
                'name': regex[0],
                'multi_context': False
            } for m in re.finditer(r, content)]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex, item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items

def parser_input(input):
    ''' Parser Input '''
    # method 1 - url
    schemes = ('http://', 'https://', 'ftp://', 'file://', 'ftps://')
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]
    # method 3 - local file
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (paths if len(paths) > 0 else [None])
    if os.path.exists(input):
        try:
            with open(input, 'r') as file:
                urls = file.readlines()
                urls = [url.strip() for url in urls]
                return urls
        except Exception as e:
            print(f"{RED}Error: {WHITE}{e}{RESET}")
            return [None]
    else:
        while True:
            print(f"{RED}Error: {WHITE}file could not be found (maybe you forgot to add http/https).{RESET}")
            print(f"{GREEN}Please enter a URL that starts with http://, https://, ftp://, file://, or ftps://{RESET}")
            input = input("Enter a URL: ")
            if input.startswith(schemes):
                return [input]
            elif input.startswith('view-source:'):
                return [input[12:]]
            elif '*' in input:
                paths = glob.glob(os.path.abspath(input))
                for index, path in enumerate(paths):
                    paths[index] = "file://%s" % path
                return (paths if len(paths) > 0 else [None])
            elif os.path.exists(input):
                try:
                    with open(input, 'r') as file:
                        urls = file.readlines()
                        urls = [url.strip() for url in urls]
                        return urls
                except Exception as e:
                    print(f"{RED}Error: {WHITE}{e}{RESET}")
                    return [None]

def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(f"{GREEN}{match.get('name')}{RESET}\t ->\t{YELLOW}{match.get('matched').encode('ascii', 'ignore').decode('utf-8')}{RESET}")

def urlParser(url):
    ''' urlParser '''
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc
    urlParser.this_path = parse.scheme + '://' + parse.netloc + '/' + parse.path

def extractjsurl(content, base_url):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath('//script'):
        src = src.xpath('@src')[0] if src.xpath('@src') != [] else []
        if src != [] and not src.startswith('http://localhost'):
            if src.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('//'):
                src = 'http://' + src[2:]
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('/'):
                src = urlParser.this_root + src
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src
                if src not in all_src:
                    all_src.append(src)
    # Remove any URLs that contain '../' in the path
    all_src = [src for src in all_src if '../' not in src]
    return all_src

def send_request(url, cookie=None, browser=None):
    """Send a request to the specified URL and return the browser and content."""
    if browser is None:
        browser = initialize_browser()
    
    try:
        browser.get(url)
        if cookie:
            cookies = browser.get_cookies()
            cookie_string = ''
            for cookie in cookies:
                cookie_string += f"{cookie['name']}={cookie['value']}; "
            cookie = cookie_string
            print(f"{WHITE} Cookies captured: {cookie_string}{RESET}")
    except WebDriverException as e:
        print(f"{RED}Error: {WHITE}{e}{RESET}")
        print("Error: Unable to detect browser. Please install a supported browser.")
        sys.exit(1)
    
    content = browser.page_source
    return browser, content

def initialize_browser():
    """Initialize a browser instance."""
    try:
        options = ChromeOptions()
        return webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
    except (WebDriverException, SessionNotCreatedException) as e:
        try:
            options = FirefoxOptions()
            return webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
        except (WebDriverException, SessionNotCreatedException) as e:
            try:
                options = EdgeOptions()
                return webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
            except (WebDriverException, SessionNotCreatedException) as e:
                print("Error: Unable to detect browser. Please install a supported browser.")
                sys.exit(1)

def browser_interaction(browser, url):
    try:
        browser.get(url)
    except WebDriverException as e:
        print(f"{RED}Error: {WHITE}{e}{RESET}")
        print(f"{GREEN}Browser closed or force-closed. Do you want to continue? (y/n){RESET}")
        choice = input().lower()
        if choice == 'y':
            # Re-initialize the browser
            browser = None
            try:
                options = ChromeOptions()
                browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
            except (WebDriverException, SessionNotCreatedException) as e:
                try:
                    options = FirefoxOptions()
                    browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                except (WebDriverException, SessionNotCreatedException) as e:
                    try:
                        options = EdgeOptions()
                        browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                    except (WebDriverException, SessionNotCreatedException) as e:
                        print("Error: Unable to detect browser. Please install a supported browser.")
                        sys.exit(1)
            except NoSuchWindowException as e:
                print(f"Error: {e}")
                print("Error: Unable to detect browser. Please install a supported browser.")
                sys.exit(1)
            # Continue with the script
            browser.get(url)
        else:
            print(f"{RED}Exiting the script.{RESET}")
            sys.exit(0)
    return browser

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(f"{RED}Error: {WHITE}{message}{RESET}")
        self.print_help()
        sys.exit(0)

def main():
    try:
        print_banner()
        parser = CustomArgumentParser()
        parser.add_argument("-i", "--input", help=f"{MAGENTA}Input a: URL, file or folder{RESET}", action="store")
        parser.add_argument("-r", "--regex", help=f"{BLUE}RegEx for filtering purposes against found endpoint (e.g: ^/api/){RESET}", action="store")
        parser.add_argument("-uf", "--urlfile", help=f"{BLUE}Read URLs from a text file{RESET}", action="store")
        parser.epilog = f"{BLUE}Example: {WHITE}python3 jspector.py -i https://example.com or python3 jspector.py -i file:///home/kali/Desktop/test.txt or python3 jspector.py -uf /home/kali/Desktop/urls.txt{RESET}"
        args = parser.parse_args()

        if args.input:
            if args.input.startswith("file://"):
                print(f"{BLUE}Opening file path directly...{RESET}")
                file_path = args.input.replace("file://", "")
                browser = None
                try:
                    options = ChromeOptions()
                    browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                except (WebDriverException, SessionNotCreatedException) as e:
                    try:
                        options = FirefoxOptions()
                        browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                    except (WebDriverException, SessionNotCreatedException) as e:
                        try:
                            options = EdgeOptions()
                            browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                        except (WebDriverException, SessionNotCreatedException) as e:
                            print("Error: Unable to detect browser. Please install a supported browser.")
                            sys.exit(1)
                browser.get("file://" + file_path)
                with open(file_path, 'r') as file:
                    content = file.read()
                    matched = parser_file(content)
                    cli_output(matched)
                print(f"{GREEN} Done!{RESET}")
                browser.quit()
            else:
                if args.input[-1:] == "/":
                    # /aa/ -> /aa
                    args.input = args.input[:-1]

                # add args
                if args.regex:
                    # validate regular exp
                    try:
                        r = re.search(args.regex, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10, 50))))
                    except Exception as e:
                        print('your python regex isn\'t valid')
                        sys.exit()

                    _regex.update({
                        'custom_regex': args.regex
                    })

                # convert input to URLs or JS files
                urls = parser_input(args.input)

                cookie = None
                print(f"{GREEN} Do you want to login or register in the website ? If yes, please type 'y ', otherwise type 'n'.{RESET}")
                choice = input().lower()
                if choice == 'y':
                    browser = None
                    try:
                        options = ChromeOptions()
                        browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                    except (WebDriverException, SessionNotCreatedException) as e:
                        try:
                            options = FirefoxOptions()
                            browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                        except (WebDriverException, SessionNotCreatedException) as e:
                            try:
                                options = EdgeOptions()
                                browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                            except (WebDriverException, SessionNotCreatedException) as e:
                                print("Error: Unable to detect browser. Please install a supported browser.")
                                sys.exit(1)
                    except NoSuchWindowException as e:
                        print(f"Error: {e}")
                        print("Error: Unable to detect browser. Please install a supported browser.")
                        sys.exit(1)

                    browser.get(args.input)
                    print(f"{WHITE} Please login or register to the page.{RESET}")
                    print(f"{WHITE} Type 'go' when you're done: {RESET}")
                    while True:
                        done = input().lower()
                        if done == 'go':
                            cookies = browser.get_cookies()
                            cookie_string = ''
                            for cookie in cookies:
                                cookie_string += f"{cookie['name']}={cookie['value']}; "
                            cookie = cookie_string
                            print(f"{WHITE} Cookies captured: {cookie_string}{RESET}")
                            break
                        else:
                            print(f"{GREEN} Please type 'go' when you're done.{RESET}")

                    # Continue with the script in the same browser
                    browser, content = send_request(args.input, cookie, browser)
                elif choice == 'n':
                    print(f"{WHITE} Continuing without cookies.{RESET}")
                    browser = None
                    try:
                        options = ChromeOptions()
                        browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                    except (WebDriverException, SessionNotCreatedException) as e:
                        try:
                            options = FirefoxOptions()
                            browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                        except (WebDriverException, SessionNotCreatedException) as e:
                            try:
                                options = EdgeOptions()
                                browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                            except (WebDriverException, SessionNotCreatedException) as e:
                                print("Error: Unable to detect browser. Please install a supported browser.")
                                sys.exit(1)
                    except NoSuchWindowException as e:
                        print(f"Error: {e}")
                        print("Error: Unable to detect browser. Please install a supported browser.")
                        sys.exit(1)

                    browser, content = send_request(args.input, cookie, browser)
                else:
                    print(f"{WHITE} Invalid choice. Continuing without cookies.{RESET}")
                    browser = None
                    try:
                        options = ChromeOptions()
                        browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                    except (WebDriverException, SessionNotCreatedException) as e:
                        try:
                            options = FirefoxOptions()
                            browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                        except (WebDriverException, SessionNotCreatedException) as e:
                            try:
                                options = EdgeOptions()
                                browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                            except (WebDriverException, SessionNotCreatedException) as e:
                                print("Error: Unable to detect browser. Please install a supported browser.")
                                sys.exit(1)
                    except NoSuchWindowException as e:
                        print(f"Error: {e}")
                        print("Error: Unable to detect browser. Please install a supported browser.")
                        sys.exit(1)

                    browser, content = send_request(args.input, cookie, browser)

                processed_urls = set()

                for url in urls:
                    try:
                        if browser is None:
                            browser, content = send_request(url, cookie)
                        else:
                            browser = browser_interaction(browser, url)
                            content = browser.page_source

                        response = requests.get(url)
                        if 300 <= response.status_code < 400:
                            redirect_url = response.headers['Location']
                            if redirect_url not in processed_urls:
                                processed_urls.add(redirect_url)
                                print(f"{YELLOW}[ + ] Redirected URL: {redirect_url}{RESET}")
                                browser = browser_interaction(browser, redirect_url)
                                content = browser.page_source
                                matched = parser_file(content)
                                cli_output(matched)

                                # extract JavaScript links from the redirected URL
                                js_urls = extractjsurl(content, redirect_url)
                                for js_url in js_urls:
                                    if js_url not in processed_urls:
                                        processed_urls.add(js_url)
                                        print(f"{YELLOW}[ + ] JS URL: {js_url}{RESET}")
                                        browser = browser_interaction(browser, js_url)
                                        content = browser.page_source
                                        matched = parser_file(content)
                                        cli_output(matched)
                        else:
                            # No redirect, process the initial URL
                            matched = parser_file(content)
                            cli_output(matched)
                            js_urls = extractjsurl(content, url)
                            for js_url in js_urls:
                                if js_url not in processed_urls:
                                    processed_urls.add(js_url)
                                    print(f"{YELLOW}[ + ] JS URL: {js_url}{RESET}")
                                    browser = browser_interaction(browser, js_url)
                                    content = browser.page_source
                                    matched = parser_file(content)
                                    cli_output(matched)
                    except requests.exceptions.RequestException as e:
                        print(f"Error: {e}")
                if browser is not None:
                    browser.quit()
                print(f"{GREEN} Done!{RESET}")
        elif args.urlfile:
            try:
                with open(args.urlfile, 'r') as file:
                    urls = file.readlines()
                    urls = [url.strip() for url in urls]
                for url in urls:
                    print(f"{CYAN}Processing URL: {url}{RESET}")
                    args.input = url
                    if args.input.startswith("file://"):
                        print(f"{BLUE}Opening file path directly...{RESET}")
                        file_path = args.input.replace("file://", "")
                        browser = None
                        try:
                            options = ChromeOptions()
                            browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                        except (WebDriverException, SessionNotCreatedException) as e:
                            try:
                                options = FirefoxOptions()
                                browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                            except (WebDriverException, SessionNotCreatedException) as e:
                                try:
                                    options = EdgeOptions()
                                    browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                                except (WebDriverException, SessionNotCreatedException) as e:
                                    print("Error: Unable to detect browser. Please install a supported browser.")
                                    sys.exit(1)
                        browser.get("file://" + file_path)
                        with open(file_path, 'r') as file:
                            content = file.read()
                            matched = parser_file(content)
                            cli_output(matched)
                        print(f"{GREEN} Done!{RESET}")
                        browser.quit()
                    else:
                        if args.input[-1:] == "/":
                            # /aa/ -> /aa
                            args.input = args.input[:-1]

                        # add args
                        if args.regex:
                            # validate regular exp
                            try:
                                r = re.search(args.regex, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10, 50))))
                            except Exception as e:
                                print('your python regex isn\'t valid')
                                sys.exit()

                            _regex.update({
                                'custom_regex': args.regex
                            })

                        # convert input to URLs or JS files
                        urls = parser_input(args.input)

                        cookie = None
                        print(f"{GREEN} Do you want to login or register in the website ? If yes, please type 'y ', otherwise type 'n'.{RESET}")
                        choice = input().lower()
                        if choice == 'y':
                            browser = None
                            try:
                                options = ChromeOptions()
                                browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                            except (WebDriverException, SessionNotCreatedException) as e:
                                try:
                                    options = FirefoxOptions()
                                    browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                                except (WebDriverException, SessionNotCreatedException) as e:
                                    try:
                                        options = EdgeOptions()
                                        browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                                    except (WebDriverException, SessionNotCreatedException) as e:
                                        print("Error: Unable to detect browser. Please install a supported browser.")
                                        sys.exit(1)
                            except NoSuchWindowException as e:
                                print(f"Error: {e}")
                                print("Error: Unable to detect browser. Please install a supported browser.")
                                sys.exit(1)

                            browser.get(args.input)
                            print(f"{WHITE} Please login or register to the page.{RESET}")
                            print(f"{WHITE} Type 'go' when you're done: {RESET}")
                            while True:
                                done = input().lower()
                                if done == 'go':
                                    cookies = browser.get_cookies()
                                    cookie_string = ''
                                    for cookie in cookies:
                                        cookie_string += f"{cookie['name']}={cookie['value']}; "
                                    cookie = cookie_string
                                    print(f"{WHITE} Cookies captured: {cookie_string}{RESET}")
                                    break
                                else:
                                    print(f"{GREEN} Please type 'go' when you're done.{RESET}")

                            # Continue with the script in the same browser
                            browser, content = send_request(args.input, cookie, browser)
                        elif choice == 'n':
                            print(f"{WHITE} Continuing without cookies.{RESET}")
                            browser = None
                            try:
                                options = ChromeOptions()
                                browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                            except (WebDriverException, SessionNotCreatedException) as e:
                                try:
                                    options = FirefoxOptions()
                                    browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                                except (WebDriverException, SessionNotCreatedException) as e:
                                    try:
                                        options = EdgeOptions()
                                        browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                                    except (WebDriverException, SessionNotCreatedException) as e:
                                        print("Error: Unable to detect browser. Please install a supported browser.")
                                        sys.exit(1)
                            except NoSuchWindowException as e:
                                print(f"Error: {e}")
                                print("Error: Unable to detect browser. Please install a supported browser.")
                                sys.exit(1)

                            browser, content = send_request(args.input, cookie, browser)
                        else:
                            print(f"{WHITE} Invalid choice. Continuing without cookies.{RESET}")
                            browser = None
                            try:
                                options = ChromeOptions()
                                browser = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                            except (WebDriverException, SessionNotCreatedException) as e:
                                try:
                                    options = FirefoxOptions()
                                    browser = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
                                except (WebDriverException, SessionNotCreatedException) as e:
                                    try:
                                        options = EdgeOptions()
                                        browser = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)
                                    except ( WebDriverException, SessionNotCreatedException) as e:
                                        print("Error: Unable to detect browser. Please install a supported browser.")
                                        sys.exit(1)
                            except NoSuchWindowException as e:
                                print(f"Error: {e}")
                                print("Error: Unable to detect browser. Please install a supported browser.")
                                sys.exit(1)

                            browser, content = send_request(args.input, cookie, browser)

                        processed_urls = set()

                        for url in urls:
                            try:
                                if browser is None:
                                    browser, content = send_request(url, cookie)
                                else:
                                    browser = browser_interaction(browser, url)
                                    content = browser.page_source

                                response = requests.get(url)
                                if 300 <= response.status_code < 400:
                                    redirect_url = response.headers['Location']
                                    if redirect_url not in processed_urls:
                                        processed_urls.add(redirect_url)
                                        print(f"{YELLOW}[ + ] Redirected URL: {redirect_url}{RESET}")
                                        browser = browser_interaction(browser, redirect_url)
                                        content = browser.page_source
                                        matched = parser_file(content)
                                        cli_output(matched)

                                        # extract JavaScript links from the redirected URL
                                        js_urls = extractjsurl(content, redirect_url)
                                        for js_url in js_urls:
                                            if js_url not in processed_urls:
                                                processed_urls.add(js_url)
                                                print(f"{YELLOW}[ + ] JS URL: {js_url}{RESET}")
                                                browser = browser_interaction(browser, js_url)
                                                content = browser.page_source
                                                matched = parser_file(content)
                                                cli_output(matched)
                                else:
                                    # No redirect, process the initial URL
                                    matched = parser_file(content)
                                    cli_output(matched)
                                    js_urls = extractjsurl(content, url)
                                    for js_url in js_urls:
                                        if js_url not in processed_urls:
                                            processed_urls.add(js_url)
                                            print(f"{YELLOW}[ + ] JS URL: {js_url}{RESET}")
                                            browser = browser_interaction(browser, js_url)
                                            content = browser.page_source
                                            matched = parser_file(content)
                                            cli_output(matched)
                            except requests.exceptions.RequestException as e:
                                print(f"Error: {e}")
                        if browser is not None:
                            browser.quit()
                        print(f"{GREEN} Done!{RESET}")
            except Exception as e:
                print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nCtrl+C pressed. Exiting...")
        sys.exit(0)
        
if __name__ == "__main__":
    main()
