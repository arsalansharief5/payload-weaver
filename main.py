from datetime import datetime
import time
import requests
from termcolor import colored
import crawler
import attack
import report_generator
from connection import connect_to_zap, get_zap_version
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import certifi

urllib3.disable_warnings(InsecureRequestWarning)
def main():
    zap_url =  "https://localhost:8080"  # Adjusted URL to use https and port 8081
    api_key = "d4b8srkheoju3qe1uo8v6pm2k4" # Replace with your actual API key

    print(colored("Initializing connection to ZAP...", "blue"))
    zap = connect_to_zap(zap_url)
    if not zap:
        print(colored("Failed to connect to ZAP after 3 retries.", "red"))
        return

    print(colored(f"Connection successful! ZAP Version: {get_zap_version(zap)}", "green"))

    # Create a new session in ZAP
    create_zap_session(zap_url, api_key)

    target_url = input("Enter the URL you want to test or perform attacks on (e.g., https://example.com): ").strip()

    # Start time for scan
    start_time = time.time()

    print(colored("Starting website crawl...", "blue"))
    crawl_data = crawler.crawl_website(zap, target_url)

    print(colored(f"Crawling complete! {crawl_data['num_crawls']} URLs crawled.", "green"))

    perform_attack = input("Do you want to attack the site? (yes/no): ").strip().lower()
    vulnerabilities = []
    attack_type = ""

    if perform_attack == "yes":
        attack_mode = input("Choose attack mode (1. XSS, 2. SQL Injection, 3. Command Injection, 4. All): ").strip()
        if attack_mode == "1":
            print(colored("Starting XSS attack...", "yellow"))
            vulnerabilities = attack.attack_website(zap, target_url, attack_type="xss")
            attack_type = "XSS"
        elif attack_mode == "2":
            print(colored("Starting SQL Injection attack...", "yellow"))
            vulnerabilities = attack.attack_website(zap, target_url, attack_type="sql_injection")
            attack_type = "SQL Injection"
        elif attack_mode == "3":
            print(colored("Starting Command Injection attack...", "yellow"))
            vulnerabilities = attack.attack_website(zap, target_url, attack_type="command_injection")
            attack_type = "Command Injection"
        elif attack_mode == "4":
            print(colored("Starting all attacks...", "yellow"))
            vulnerabilities = attack.attack_website(zap, target_url, attack_type="all")
            attack_type = "All Attacks"

    # End time for scan
    end_time = time.time()

    # Calculate scan duration
    scan_duration = round(end_time - start_time, 2)

    # Display counts of vulnerabilities in the terminal
    high_count = len([v for v in vulnerabilities if v['risk'] == "High"])
    medium_count = len([v for v in vulnerabilities if v['risk'] == "Medium"])
    low_count = len([v for v in vulnerabilities if v['risk'] == "Low"])

    print(colored(f"\nVulnerabilities Found for {attack_type}:", "yellow"))
    print(f"- High Severity: {high_count}")
    print(f"- Medium Severity: {medium_count}")
    print(f"- Low Severity: {low_count}")
    
    print(colored("Generating report...", "yellow"))
    # Pass the scan duration, counts, and start/end times for report generation
    start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_generator.generate_report(
        crawl_data=crawl_data,
        target_url=target_url,
        perform_attack=perform_attack,
        vulnerabilities=vulnerabilities,
        scan_duration=scan_duration,
        start_time=start_time_str,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        attack_type=attack_type  # Add attack type for clarity in the report
    )

def create_zap_session(zap_url, api_key):
    """Creates a new session in ZAP"""
    params = {
        'name': 'new_session',  # Custom session name
        'overwrite': 'true',    # Overwrite existing session if any
        'apikey': api_key       # API key for authentication
    }

    try:
        response = requests.get(f'{zap_url}/JSON/core/action/newSession/', params=params,verify=False,
                                 timeout=30)
        if response.status_code == 200:
            print(colored("New session created successfully.", "green"))
        else:
            print(colored(f"Failed to create session. Response: {response.json()}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"Error creating session: {e}", "red"))

def check_zap_status():
    """Check if the ZAP API is running and accessible"""
    try:
        zap_url = "https://localhost:8080"  # Updated URL for HTTPS and port 8081
        response = requests.get(zap_url, verify=False)
        
        if response.status_code == 200:
            print("Successfully connected to ZAP API.")
            return True
        else:
            print(f"Failed to connect to ZAP API, status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to ZAP: {e}")
        return False

if __name__ == "__main__":
    main()