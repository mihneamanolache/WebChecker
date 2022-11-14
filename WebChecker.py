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

no_cms_flag = True
wordpress_flg = False
joomla_flag = False
drupal_flag = False
certainty = 0
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

    IP = socket.gethostbyname(url_socket)

    cprint(f'[*] Checking: {url}...', 'yellow')
    cprint(f'[!] {url} seems to be online', 'green')
    print('')
    
    cprint("[*] Attempting to identify potential CMS...", 'yellow')


    # ------ CHECKING WORDPRESS ------ #
    cprint("[!] Running WordPress scans...", 'magenta')
    
    wordpress_flg_url = requests.get(url_request + '/wp-login.php', allow_redirects=True, headers=user_agent)
    if wordpress_flg_url.status_code == 200 and "user_login" in wordpress_flg_url.text and "404" not in wordpress_flg_url.text:
        cprint(f"    [+] WordPress login page available at {url_request}/wp-login.php", 'green')
        no_cms_flag = False
        wordpress_flg = True
        certainty += 25
    else:
        cprint(f"    [-] WordPress login page not available", 'red')
    
    wordpress_flg_url = requests.get(url_request + '/wp-admin/upgrade.php', allow_redirects=False, headers=user_agent)
    if wordpress_flg_url.status_code == 200 and "404" not in wordpress_flg_url.text:
        no_cms_flag = False
        wordpress_flg = True
        cprint(f"    [+] WP-Admin/upgrade.php page available at {url_request}/wp-admin/upgrade.php", 'green')
        if certainty == 100:
            pass
        else:    
            certainty += 25
    else:
        cprint(f"    [-] WP-Admin/upgrade.php page not available", 'red')
    
    wordpress_flg_url = requests.get(url_request + '/wp-json/wp/v2/', allow_redirects=False, headers=user_agent)
    if wordpress_flg_url.status_code == 200 and "404" not in wordpress_flg_url.text:
        no_cms_flag = False
        wordpress_flg = True
        cprint(f"    [+] WP API available at {url_request}/wp-json/wp/v2/", 'green')
        if certainty == 100:
            pass
        else:    
            certainty += 25
    else:
        cprint(f"    [-] WP API not available", 'red')
    
    wordpress_flg_url = requests.get(url_request + '/robots.txt', allow_redirects=True, headers=user_agent)
    if wordpress_flg_url.status_code == 200 and "wp-admin" in wordpress_flg_url.text:
        no_cms_flag = False
        wordpress_flg = True
        cprint(f"    [+] Robots.txt fount at {url_request}/robots.txt containing 'wp_admin'", 'green')
        if certainty == 100:
            pass
        else:    
            certainty += 25
    else:
        cprint(f"    [-] Robots.txt not found", 'red')
    
    # ------ CHECKING JOOMLA ------ #
    cprint("[!] Running Joomla scans...", 'magenta')

    joomla_flag_url = requests.get(url_request + '/administrator/')
    if joomla_flag_url.status_code == 200 and "mod-login-username" in joomla_flag_url.text and "404" not in joomla_flag_url.text:
        no_cms_flag = False
        joomla_flag = True
        cprint(f"    [+] {url_request} seems to be running on Joomla", 'green')
        certainty += 100
    else:
        cprint(f"    [-] {url_request} doesn't seem to be running on Joomla", 'red')
   
    # ------ CHECKING DRUPAL ------ #
    cprint("[!] Running Drupal scans...", 'magenta')

    drupal_flag_url = requests.get(url_request + '/readme.txt')
    if drupal_flag_url.status_code == 200 and 'drupal' in drupal_flag_url.text and '404' not in drupal_flag_url.text:
        no_cms_flag = False
        drupal_flag = True
        certainty += 33
        cprint(f"    [+] Drupal Readme.txt detected at {url_request}/readme.txt", 'green')
    else:
        cprint(f"    [-] Drupal Readme.txt not detected", 'red')

    drupal_flag_url = requests.get(url_request)
    if drupal_flag_url.status_code == 200 and 'name="Generator" content="Drupal' in drupal_flag_url.text:
        no_cms_flag = False
        drupal_flag = True
        certainty += 33
        cprint(f"    [+] Drupal strings detected.", 'green')
    else:
        cprint(f"    [-] No Drupal string detected", 'red')

    drupal_flag_url = requests.get(url_request + '/modules/README.txt')
    if drupal_flag_url.status_code == 200 and 'drupal' in drupal_flag_url.text and '404' not in drupal_flag_url.text:
        no_cms_flag = False
        drupal_flag = True
        certainty += 33
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
    if no_cms_flag:
        cprint(f"   [!] {url} doesn't seem to run any known CMS", 'yellow')
    elif wordpress_flg:
        cprint(f"   [+] {url} seems to be running WordPress. [certainty: {certainty}%]", 'green')
    elif joomla_flag:
        cprint(f"   [+] {url} seems to be running Joomla. [certainty: {certainty}%]", 'green')
    elif drupal_flag:
        cprint(f"   [+] {url} seems to be running Drupal. [certainty: {certainty}%]", 'green')
    cprint(f'   [+] HTTP Status:    {status}', 'green')
    cprint(f'   [+] Server type:    {server_type}', 'green')
    cprint(f'   [+] Server IP:      {IP}', 'green')
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
