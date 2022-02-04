import requests
import socket
import argparse
from termcolor import cprint
import os

######################## ARGUMENTS ########################

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", help="Specify the URL ypu want to Check")
parser.add_argument("-b", "--brute", help="Attempt to bruteforce interesting directories")
args = parser.parse_args()

########################  GLOBALS  ########################

CMS_error = True
WP = False
JOOM = False
MAG = False
DRUP = False
confidence = 0
url = ''
url_request = ''
url_socket = ''
user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36',}
banner = ('''
__          __  _      _____ _               _               __   ___  
\ \        / / | |    / ____| |             | |             /_ | / _ \ 
 \ \  /\  / /__| |__ | |    | |__   ___  ___| | _____ _ __   | || | | |
  \ \/  \/ / _ \ '_ \| |    | '_ \ / _ \/ __| |/ / _ \ '__|  | || | | |
   \  /\  /  __/ |_) | |____| | | |  __/ (__|   <  __/ |     | || |_| |
    \/  \/ \___|_.__/ \_____|_| |_|\___|\___|_|\_\___|_|     |_(_)___/ 

                            by mihnaemanolache
                    https://github.com/mihneamanolache/
    ''')
term_size = os.get_terminal_size()
COMMAND = 'clear'
if os.name in ('nt', 'dos'):  
    COMMAND = 'cls'
########################  RUNNING  ########################

os.system(COMMAND)
cprint(banner, 'blue')
cprint('-'*term_size.columns, 'blue')

if args.url is None:
        # Get the input from the user
        url = input('Site to check: ')
        cprint('-'*term_size.columns, 'blue')
else:
    url = args.url

try:
    if url.startswith('http'):
        url_request = url
        url_socket = url.lstrip('http')
        url_socket = url_socket.lstrip('s')
        url_socket = url_socket.lstrip('://')
        url_socket = url_socket.rstrip('/')
    else:
        url_request = 'http://' + url    
        url_socket = url
    
    r = requests.get(url_request, allow_redirects=True, headers=user_agent)

    IP_addres = socket.gethostbyname(url_socket)

    cprint(f'[*] Checking: {url}...', 'yellow')
    cprint(f'[!] {url} seems to be online', 'green')
    print('')
    
    cprint("[*] Attempting to identify potential CMS...", 'yellow')


    # ------ CHECKING WORDPRESS ------ #
    cprint("[!] Running WordPress scans...", 'magenta')
    
    wp_url = requests.get(url_request + '/wp-login.php', allow_redirects=True, headers=user_agent)
    if wp_url.status_code == 200 and "user_login" in wp_url.text and "404" not in wp_url.text:
        cprint(f"    [+] WordPress login page available at {url_request}/wp-login.php", 'green')
        CMS_error = False
        WP = True
        confidence += 25
    else:
        cprint(f"    [-] WordPress login page not available", 'red')
    
    wp_url = requests.get(url_request + '/wp-admin/upgrade.php', allow_redirects=False, headers=user_agent)
    if wp_url.status_code == 200 and "404" not in wp_url.text:
        CMS_error = False
        WP = True
        cprint(f"    [+] WP-Admin/upgrade.php page available at {url_request}/wp-admin/upgrade.php", 'green')
        if confidence == 100:
            pass
        else:    
            confidence += 25
    else:
        cprint(f"    [-] WP-Admin/upgrade.php page not available", 'red')
    
    wp_url = requests.get(url_request + '/wp-json/wp/v2/', allow_redirects=False, headers=user_agent)
    if wp_url.status_code == 200 and "404" not in wp_url.text:
        CMS_error = False
        WP = True
        cprint(f"    [+] WP API available at {url_request}/wp-json/wp/v2/", 'green')
        if confidence == 100:
            pass
        else:    
            confidence += 25
    else:
        cprint(f"    [-] WP API not available", 'red')
    
    wp_url = requests.get(url_request + '/robots.txt', allow_redirects=True, headers=user_agent)
    if wp_url.status_code == 200 and "wp-admin" in wp_url.text:
        CMS_error = False
        WP = True
        cprint(f"    [+] Robots.txt fount at {url_request}/robots.txt containing 'wp_admin'", 'green')
        if confidence == 100:
            pass
        else:    
            confidence += 25
    else:
        cprint(f"    [-] Robots.txt not found", 'red')
    
    # ------ CHECKING JOOMLA ------ #
    cprint("[!] Running Joomla scans...", 'magenta')

    joom_url = requests.get(url_request + '/administrator/')
    if joom_url.status_code == 200 and "mod-login-username" in joom_url.text and "404" not in joom_url.text:
        CMS_error = False
        JOOM = True
        cprint(f"    [+] {url_request} seems to be running on Joomla", 'green')
        confidence += 100
    else:
        cprint(f"    [-] {url_request} doesn't seem to be running on Joomla", 'red')

    # ------ CHECKING MAGENTO ------ #
    cprint("[!] Running Magento scans...", 'magenta')

    mag_url = requests.get(url_request + '/index.php', allow_redirects=False)
    if mag_url.status_code == 200 and '/mage/' in mag_url.text or 'magento' in mag_url.text:
        CMS_error = False
        MAG = True
        confidence += 25
        cprint(f"    [+] Magento strings detected.", 'green')
    else:
        cprint(f"    [-] No Magento strings detected", 'red')
        
    mag_url = requests.get(url_request + '/index.php/admin/', allow_redirects=False)
    if mag_url.status_code == 200 and 'login' in mag_url.text and "404" not in mag_url.text:
        CMS_error = False
        MAG = True   
        confidence += 25     
        cprint(f"    [+] Potential Magento admin login at {url_request}/index.php/admin/", 'green')
    else:
        cprint(f"    [-] {url_request}/index.php/admin/ not available", 'red')
    
    mag_url = requests.get(url_request + '/RELEASE_NOTES.txt')
    if mag_url.status_code == 200 and 'magento' in mag_url.text:
        CMS_error = False
        MAG = True   
        confidence += 25     
        cprint(f"    [+] Magento Release_Notes.txt detected at {url_request}/RELEASE_NOTES.txt", 'green')
    else:
        cprint(f"    [-] Magento Release_Notes.txt not detected", 'red')
    
    mag_url = requests.get(url_request + '/js/mage/cookies.js')
    if mag_url.status_code == 200 and "404" not in mag_url.text:
        CMS_error = False
        MAG = True    
        confidence += 25    
        cprint(f"    [+] Magento cookies.js detected at {url_request}/js/mage/cookies.jst", 'green')
    else:
        cprint(f"    [-] Magento cookies.js not detected", 'red') 

    # ------ CHECKING DRUPAL ------ #
    cprint("[!] Running Drupal scans...", 'magenta')

    drup_url = requests.get(url_request + '/readme.txt')
    if drup_url.status_code == 200 and 'drupal' in drup_url.text and '404' not in drup_url.text:
        CMS_error = False
        DRUP = True
        confidence += 33
        cprint(f"    [+] Drupal Readme.txt detected at {url_request}/readme.txt", 'green')
    else:
        cprint(f"    [-] Drupal Readme.txt not detected", 'red')

    drup_url = requests.get(url_request)
    if drup_url.status_code == 200 and 'name="Generator" content="Drupal' in drup_url.text:
        CMS_error = False
        DRUP = True
        confidence += 33
        cprint(f"    [+] Drupal strings detected.", 'green')
    else:
        cprint(f"    [-] No Drupal string detected", 'red')

    drup_url = requests.get(url_request + '/modules/README.txt')
    if drup_url.status_code == 200 and 'drupal' in drup_url.text and '404' not in drup_url.text:
        CMS_error = False
        DRUP = True
        confidence += 33
        cprint(f"    [+] Drupal modules detected at {url_request}/modules/README.txt", 'green')
    else:
        cprint(f"    [-] No Drupal modules detected", 'red')

    print('')
    cprint('-'*term_size.columns, 'blue')

    # ------ DISPLAY APP OVERVIEW ------ #
    status = r.status_code
    server_type = r.headers['Server']
    cprint('App overview:', 'magenta')
    cprint(f'   [+] {url} is available', 'green')
    if CMS_error:
        cprint(f"   [!] {url} doesn't seem to run any known CMS", 'yellow')
    elif WP:
        cprint(f"   [+] {url} seems to be running WordPress. [Confidence: {confidence}%]", 'green')
    elif JOOM:
        cprint(f"   [+] {url} seems to be running Joomla. [Confidence: {confidence}%]", 'green')
    elif MAG:
        cprint(f"   [+] {url} seems to be running Magento. [Confidence: {confidence}%]", 'green')
    elif DRUP:
        cprint(f"   [+] {url} seems to be running Drupal. [Confidence: {confidence}%]", 'green')
    cprint(f'   [+] HTTP Status:    {status}', 'green')
    cprint(f'   [+] Server type:    {server_type}', 'green')
    cprint(f'   [+] Server IP:      {IP_addres}', 'green')
    print('')
    cprint('-'*term_size.columns, 'blue')
    
     # ------ DISPLAY HEADERS ------ #
    cprint('Detailed HTTP header report:', 'magenta')
    for i in r.headers: # -> Printare Headers pe linii (prettyprint)
        cprint(f"   [*] {i}: {r.headers[i]}", 'cyan') 
    print('')

# ------ ERROR: INVALID URL ------ #
except requests.exceptions.RequestException as e: 
    cprint(f'[!] Checking: {url}...', 'yellow')
    print('')
    cprint('ERROR! It seems like the URL you provided is incorrect or the WebApp is not connected to the Internet', 'red')
    print('')
    cprint('ERROR MESSAGE:', 'yellow', end=' ')
    raise SystemExit(e)

# ------ BRUTE FORCING DIRECTORIES ------ #
if args.brute:
    cprint('-'*term_size.columns, 'blue')
    cprint('Bruteforcing interesting directories:', 'magenta')
    f = open(args.brute, 'r')
    for i in f:
        brut_url = requests.get(url_request + "/" + i.rstrip(), allow_redirects=True, headers=user_agent)
        if brut_url.status_code == 200:
            cprint(f"   [+] {i.rstrip()} -> {brut_url.url}", 'green')
        else:
            cprint(f"   [-] {i.rstrip()} -> {brut_url.url}", 'red')