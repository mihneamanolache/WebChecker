import requests
import socket
import argparse
from termcolor import cprint
import os
from pprint import pprint

# ADAUGARE ARGUMENTE 
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", help="Specify the URL ypu want to Check")
parser.add_argument("-b", "--brute", help="Attempt to bruteforce interesting directories")
args = parser.parse_args()

# Implementare DOT NOTATION in Python, pentru accesarea metondelor din dictionarul GLOBALS
class AttrDict(dict):
    def __getattr__(self, name):
        return self[name]

# OBTINE LATIMEA TERMINALULUI 
term_size = os.get_terminal_size()

# VARIABILE GLOBALE
GLOBALS = AttrDict({
    "CMS_ERROR": True,
    "WP": False,
    "JOOM": False,
    "MAG": False,
    "DRUP": False, 
    "CONFIDENCE":0,
    "MESSAGES": []
})
USER_AGENT = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36',}
BANNER = ('''
 __          __  _      _____ _               _               ___    ___  
 \ \        / / | |    / ____| |             | |             |__ \  / _ \ 
  \ \  /\  / /__| |__ | |    | |__   ___  ___| | _____ _ __     ) || | | |
   \ \/  \/ / _ \ '_ \| |    | '_ \ / _ \/ __| |/ / _ \ '__|   / / | | | |
    \  /\  /  __/ |_) | |____| | | |  __/ (__|   <  __/ |     / /_ | |_| |
     \/  \/ \___|_.__/ \_____|_| |_|\___|\___|_|\_\___|_|    |____(_)___/ 

                            by Mihnea Manolache
                   Facultatea de Inginerie si Informatica
                          Universitatea Spiru Haret
    ''')

# FUNCTIE PENTRU STERGEREA CONSOLEI / TERMINALULUI
def clear_screen():
    if os.name in ('nt', 'dos'):  
        command='cls'
    else: 
        command='clear'
    os.system(command)

def convert_url(url):
     # Conversia inputului in URL utilizabil 
    if url.startswith('http'):
        url_request = url
        url_socket = url.lstrip('http')
        url_socket = url_socket.lstrip('s')
        url_socket = url_socket.lstrip('://')
        url_socket = url_socket.rstrip('/')
    else:
        url_request = 'http://' + url    
        url_socket = url
    return {
                "url_request": url_request,
                "url_socket": url_socket
            }

def get_headers(url_request):
    r = requests.get(url_request, allow_redirects=True, headers=USER_AGENT)
    return r.headers

def get_status(url_request):
    r = requests.get(url_request, allow_redirects=True, headers=USER_AGENT)
    return r.status_code

def get_server_type(url_request):
    r = requests.get(url_request, allow_redirects=True, headers=USER_AGENT)
    return r.headers['Server']

def get_ip_address(url_socket):
    ip_address = socket.gethostbyname(url_socket)
    return ip_address

def print_results(results):
    for i in results.MESSAGES:
        if "[+]" in i:
            cprint(f"   {i}", 'green')
        elif "[-] in i":
            cprint(f"   {i}", 'red')    

def check_wp(url_request, user_agent, result):
    wp_url = requests.get(url_request + '/wp-login.php', allow_redirects=True, headers=user_agent)
    if wp_url.status_code == 200 and "user_login" in wp_url.text and "404" not in wp_url.text:
        result["CMS_ERROR"] = False
        result["WP"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append(f"[+] WordPress login page available at {url_request}/wp-login.php")
    else:
        result["MESSAGES"].append("[-] WordPress login page not available")

    wp_url = requests.get(url_request + '/wp-admin/upgrade.php', allow_redirects=False, headers=user_agent)
    if wp_url.status_code == 200 and "404" not in wp_url.text:
        result["CMS_ERROR"] = False
        result["WP"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append(f"[+] WP-Admin/upgrade.php page available at {url_request}/wp-admin/upgrade.php")
    else:
        result["MESSAGES"].append("[-] WP-Admin/upgrade.php page doesn't seem to be available")

    wp_url = requests.get(url_request + '/wp-json/wp/v2/', allow_redirects=False, headers=user_agent)
    if wp_url.status_code == 200 and "404" not in wp_url.text:
        result["CMS_ERROR"] = False
        result["WP"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append(f"[+] WP API available at {url_request}/wp-json/wp/v2/")
    else:
        result["MESSAGES"].append("[-] WP API not available")

    wp_url = requests.get(url_request + '/robots.txt', allow_redirects=True, headers=user_agent)
    if wp_url.status_code == 200 and "wp-admin" in wp_url.text:
        result["CMS_ERROR"] = False
        result["WP"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append(f"[+] Robots.txt fount at {url_request}/robots.txt containing 'wp_admin'")
    else:
        result["MESSAGES"].append("[-] Robots.txt not found")
        
    return result

def check_joom(url_request, user_agent, result):
    result["MESSAGES"].clear()
    joom_url = requests.get(url_request + '/administrator/')
    if joom_url.status_code == 200 and "mod-login-username" in joom_url.text and "404" not in joom_url.text:
        result["CMS_ERROR"] = False
        result["JOOM"] = True
        result["CONFIDENCE"] += 100
        result["MESSAGES"].append(f"[+] {url_request} seems to be running on Joomla")
    else:
        result["MESSAGES"].append(f"[-] {url_request} doesn't seem to be running on Joomla")

    return result

def check_mag(url_request, user_agent, result):
    result["MESSAGES"].clear()
    mag_url = requests.get(url_request + '/index.php', allow_redirects=False)
    if mag_url.status_code == 200 and '/mage/' in mag_url.text or 'magento' in mag_url.text:
        result["CMS_ERROR"] = False
        result["MAG"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append("[+] Magento strings detected.")
    else:
        result["MESSAGES"].append("[-] No Magento strings detected")

    mag_url = requests.get(url_request + '/index.php/admin/', allow_redirects=False)
    if mag_url.status_code == 200 and 'login' in mag_url.text and "404" not in mag_url.text:
        result["CMS_ERROR"] = False
        result["MAG"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append(f"[+] Potential Magento admin login at {url_request}/index.php/admin/")
    else:
        result["MESSAGES"].append(f"[-] {url_request}/index.php/admin/ not available")
    
    mag_url = requests.get(url_request + '/RELEASE_NOTES.txt')
    if mag_url.status_code == 200 and 'magento' in mag_url.text:
        result["CMS_ERROR"] = False
        result["MAG"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append(f"[+] Magento Release_Notes.txt detected at {url_request}/RELEASE_NOTES.txt")
    else:
        result["MESSAGES"].append(f"[-] Magento Release_Notes.txt not detected")

    mag_url = requests.get(url_request + '/js/mage/cookies.js')
    if mag_url.status_code == 200 and "404" not in mag_url.text:
        result["CMS_ERROR"] = False
        result["MAG"] = True
        result["CONFIDENCE"] += 25
        result["MESSAGES"].append(f"[+] Magento cookies.js detected at {url_request}/js/mage/cookies.jst")
    else:
        result["MESSAGES"].append("[-] Magento cookies.js not detected")

    return result

def check_drup(url_request, user_agent, result):
    result["MESSAGES"].clear()
    drup_url = requests.get(url_request + '/readme.txt')
    if drup_url.status_code == 200 and 'drupal' in drup_url.text and '404' not in drup_url.text:
        result["CMS_ERROR"] = False
        result["DRUP"] = True
        result["CONFIDENCE"] += 33
        result["MESSAGES"].append(f"[+] Drupal Readme.txt detected at {url_request}/readme.txt")
    else:
        result["MESSAGES"].append("[-] Drupal Readme.txt not detected")

    drup_url = requests.get(url_request)
    if drup_url.status_code == 200 and 'name="Generator" content="Drupal' in drup_url.text:
        result["CMS_ERROR"] = False
        result["DRUP"] = True
        result["CONFIDENCE"] += 33
        result["MESSAGES"].append("[+] Drupal strings detected.")
    else:
        result["MESSAGES"].append("[-] No Drupal string detected")

    drup_url = requests.get(url_request + '/modules/README.txt')
    if drup_url.status_code == 200 and 'drupal' in drup_url.text and '404' not in drup_url.text:
        result["CMS_ERROR"] = False
        result["DRUP"] = True
        result["CONFIDENCE"] += 33
        result["MESSAGES"].append(f"[+] Drupal modules detected at {url_request}/modules/README.txt")
    else:
        result["MESSAGES"].append("[-] No Drupal modules detected")

    return result

# STRAT APP
clear_screen()
cprint(BANNER, 'blue')
cprint('-'*term_size.columns, 'blue')

if args.url is None:
        # Get the input from the user
        url = input('Site to check: ')
        cprint('-'*term_size.columns, 'blue')
else:
    url = args.url
try:
    # Folosim functiile definite anterior pentru a obtine diferite date despre aplicatia URL
    url_request = convert_url(url)["url_request"]
    url_socket = convert_url(url)["url_socket"]
    r = get_headers(url_request)
    ip_address = get_ip_address(url_socket)

    cprint(f'[*] Checking: {url}...', 'yellow')
    cprint(f'[!] {url} seems to be online', 'green')
    print('')

    cprint("[*] Attempting to identify potential CMS...", 'yellow')
    # Efectuare verificari standard pt WordPress
    cprint("[!] Running WordPress scans...", 'magenta')
    wp_results = AttrDict(check_wp(url_request, USER_AGENT, GLOBALS))
    print_results(wp_results)

    # Efectuare verificari standard pt Joomla
    cprint("[!] Running Joomla scans...", 'magenta')
    joom_results = AttrDict(check_joom(url_request, USER_AGENT, GLOBALS))
    print_results(joom_results)

    # Efectuare verificari standard pt Magento
    cprint("[!] Running Magento scans...", 'magenta')
    mag_results = AttrDict(check_mag(url_request, USER_AGENT, GLOBALS))
    print_results(mag_results)

    # Efectuare verificari standard pt Drupal
    cprint("[!] Running Drupal scans...", 'magenta')
    drup_results = AttrDict(check_drup(url_request, USER_AGENT, GLOBALS))
    print_results(mag_results)

    print('')
    cprint('-'*term_size.columns, 'blue')

    cprint('App overview:', 'magenta')
    cprint(f'   [+] {url} is available', 'green')
    if GLOBALS.CMS_ERROR:
        cprint(f"   [!] {url} doesn't seem to run any known CMS", 'yellow')
    elif GLOBALS.WP:
        cprint(f"   [+] {url} seems to be running WordPress. [Confidence: {GLOBALS.CONFIDENCE}%]", 'green')
    elif GLOBALS.JOOM:
        cprint(f"   [+] {url} seems to be running Joomla. [Confidence: {GLOBALS.CONFIDENCE}%]", 'green')
    elif GLOBALS.MAG:
        cprint(f"   [+] {url} seems to be running Magento. [Confidence: {GLOBALS.CONFIDENCE}%]", 'green')
    elif GLOBALS.DRUP:
        cprint(f"   [+] {url} seems to be running Drupal. [Confidence: {GLOBALS.CONFIDENCE}%]", 'green')
    cprint(f'   [+] HTTP Status:    {get_status(url_request)}', 'green')
    cprint(f'   [+] Server type:    {get_server_type(url_request)}', 'green')
    cprint(f'   [+] Server IP:      {get_ip_address(url_socket)}', 'green')
    print('')
    cprint('-'*term_size.columns, 'blue')
    
     # ------ AFISARE FULL HTTP HEADERS IN TERMINAL ------ #
    cprint('Detailed HTTP header report:', 'magenta')
    for i in get_headers(url_request): # -> Printare Headers pe linii (prettyprint)
        cprint(f"   [*] {i}: {get_headers(url_request)[i]}", 'cyan') 
    print('')

# ------ EROARE: URL INVALID ------ #
except requests.exceptions.RequestException as e: 
    cprint(f'[!] Checking: {url}...', 'yellow')
    print('')
    cprint('ERROR! It seems like the URL you provided is incorrect or the WebApp is not connected to the Internet', 'red')
    print('')
    cprint('ERROR MESSAGE:', 'yellow', end=' ')
    raise SystemExit(e)

# ------ DESSCOPERIM DIRECTOARE PRIN BRUTE-FORCE (ARGUMENTUL '-b' sau '--brute' ------ #
if args.brute:
    cprint('-'*term_size.columns, 'blue')
    cprint('Bruteforcing interesting directories:', 'magenta')
    f = open(args.brute, 'r')
    for i in f:
        brut_url = requests.get(url_request + "/" + i.rstrip(), allow_redirects=True, headers=USER_AGENT)
        if brut_url.status_code == 200:
            cprint(f"   [+] {i.rstrip()} -> {brut_url.url}", 'green')
        else:
            cprint(f"   [-] {i.rstrip()} -> {brut_url.url}", 'red')