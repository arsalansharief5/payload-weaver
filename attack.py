from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import os
import time
from termcolor import colored
import requests 
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from utils import *


class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = None  
        return super().init_poolmanager(*args, **kwargs)

def load_payload(file_path):
    print("aayo")
    print(file_path)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Payload file not found: {file_path}")
    with open(file_path, "r") as file:
        return [line.strip() for line in file.readlines()]

# def attack_website(zap, target_url, scan_type, attack_type="all"):
#     mode = attack_type
    
#     xss_payloads = load_payload("Payload/xss_payload.txt")
#     sql_payloads = load_payload("Payload/sql_payload.txt")
#     cmd_injection_payloads = load_payload("Payload/cmd_injection_payload.txt")
    
#     vulnerabilities = []

#     if mode == "xss" or mode == "all":
#         vulnerabilities += perform_attack(zap, target_url, xss_payloads, "XSS")
    
#     if mode == "sql_injection" or mode == "all":
#         vulnerabilities += perform_attack(zap, target_url, sql_payloads, "SQL Injection")
    
#     if mode == "command_injection" or mode == "all":
#         vulnerabilities += perform_attack(zap, target_url, cmd_injection_payloads, "Command Injection")
    
#     return vulnerabilities


def attack_website(zap, target_url, scan_type,attack_type):
    # Load payloads
    file_path = generate_payload_file_path(target_url,attack_type)
    
    payloads = load_payload(file_path)
    print(payloads)
    # Limit payload size based on scan type
    def limit_payloads(payloads, scan_type):
        if scan_type == "quick":
            return payloads[:len(payloads) // 3]
        elif scan_type == "regular":
            return payloads[:(2 * len(payloads)) // 3]
        elif scan_type == "deep":
            return payloads  # Use full payloads
        else:
            raise ValueError(f"Invalid scan type: {scan_type}")


    final_payloads = limit_payloads(payloads, scan_type)
    
    vulnerabilities = []

    # Perform attacks for all payloads
    vulnerabilities += perform_attack(zap, target_url, final_payloads, "All")
   
    return vulnerabilities

def perform_attack(zap, target_url, payloads, attack_type):
    def send_payload(payload):
        try:
            session = requests.Session()
            session.mount('https://', SSLAdapter())
            
            response = session.get(f"{target_url}?input={payload}", timeout=30,verify=False)
            time.sleep(0.1) 
            
            return zap.core.alerts()
        
        except requests.exceptions.SSLError as ssl_error:
            print(colored(f"SSL Error: {ssl_error}", "red"))
            return []
        except requests.exceptions.RequestException as e:
            print(colored(f"Request Error: {e}", "red"))
            return []

    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(tqdm(executor.map(send_payload, payloads), total=len(payloads)))
    
    for result in results:
        vulnerabilities.extend(result)
    return vulnerabilities