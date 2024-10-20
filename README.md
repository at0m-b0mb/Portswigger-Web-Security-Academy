# PortSwigger Web Security Academy Solutions

Welcome to my **PortSwigger Web Security Academy** solutions repository. This project contains solutions to various labs provided by the academy, categorized by topics. As I progress through each topic, I will update this repository with detailed steps and solutions for each lab.

## Topics Overview

Below is a list of server-side topics. Click on each topic to view the labs. Solutions to the labs can be found by navigating to the respective folder in this repository.

---

<details>
  <summary>Server-side topics</summary>
  
  - [SQL Injection](./server-side/sql-injection/)
  - Authentication (Coming soon)
  - Path Traversal (Coming soon)
  - Command Injection (Coming soon)
  - Business Logic Vulnerabilities (Coming soon)
  - Information Disclosure (Coming soon)
  - Access Control (Coming soon)
  - File Upload Vulnerabilities (Coming soon)
  - Race Conditions (Coming soon)
  - Server-Side Request Forgery (SSRF) (Coming soon)
  - XXE Injection (Coming soon)
  - NoSQL Injection (Coming soon)
  - API Testing (Coming soon)
  - Web Cache Deception (Coming soon)
</details>

---

## SQL Injection Labs

SQL Injection is a powerful vulnerability that can allow attackers to manipulate a database, bypass authentication, and even gain full control over the application. Below are the SQL injection labs, and you can click on each lab to go to its solution folder.

<details>
  <summary>Click to expand SQL Injection Labs</summary>
  
  - [Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](./server-side/sql-injection/lab-1-sql-injection-where-clause-retrieve-hidden-data) - Solved
  - [Lab 2: SQL injection vulnerability allowing login bypass](./server-side/sql-injection/lab-2-sql-injection-login-bypass) - Solved
  - [Lab 3: SQL injection attack, querying the database type and version on Oracle](./server-side/sql-injection/lab-3-sql-injection-query-database-type-oracle) - Solved
  - [Lab 4: SQL injection attack, querying the database type and version on MySQL and Microsoft](./server-side/sql-injection/lab-4-sql-injection-query-database-type-mysql-microsoft) - Solved
  - [Lab 5: SQL injection attack, listing the database contents on non-Oracle databases](./server-side/sql-injection/lab-5-sql-injection-list-database-contents-non-oracle) - Solved
  - [Lab 6: SQL injection attack, listing the database contents on Oracle](./server-side/sql-injection/lab-6-sql-injection-list-database-contents-oracle) - Solved
  - [Lab 7: SQL injection UNION attack, determining the number of columns returned by the query](./server-side/sql-injection/lab-7-sql-injection-union-determine-columns) - Solved
  - [Lab 8: SQL injection UNION attack, finding a column containing text](./server-side/sql-injection/lab-8-sql-injection-union-find-column-text) - Solved
  - [Lab 9: SQL injection UNION attack, retrieving data from other tables](./server-side/sql-injection/lab-9-sql-injection-union-retrieve-data-other-tables) - Solved
  - [Lab 10: SQL injection UNION attack, retrieving multiple values in a single column](./server-side/sql-injection/lab-10-sql-injection-union-retrieve-multiple-values) - Solved
  - [Lab 11: Blind SQL injection with conditional responses](./server-side/sql-injection/lab-11-blind-sql-injection-conditional-responses) - Not Solved
  - [Lab 12: Blind SQL injection with conditional errors](./server-side/sql-injection/lab-12-blind-sql-injection-conditional-errors) - Not Solved
  - [Lab 13: Visible error-based SQL injection](./server-side/sql-injection/lab-13-visible-error-based-sql-injection) - Not Solved
  - [Lab 14: Blind SQL injection with time delays](./server-side/sql-injection/lab-14-blind-sql-injection-time-delays) - Not Solved
  - [Lab 15: Blind SQL injection with time delays and information retrieval](./server-side/sql-injection/lab-15-blind-sql-injection-time-delays-information-retrieval) - Not Solved
  - [Lab 16: Blind SQL injection with out-of-band interaction](./server-side/sql-injection/lab-16-blind-sql-injection-oob) - Not Solved
  - [Lab 17: Blind SQL injection with out-of-band data exfiltration](./server-side/sql-injection/lab-17-blind-sql-injection-oob-data-exfiltration) - Not Solved
  - [Lab 18: SQL injection with filter bypass via XML encoding](./server-side/sql-injection/lab-18-sql-injection-filter-bypass-xml-encoding) - Not Solved
  
</details>

---

## How to Use This Repository

1. **Clone the repository** to your local machine:
   ```bash
   git clone https://github.com/at0m-b0mb/Portswigger-Web-Security-Academy.git

For more information about all the labs, visit the [PortSwigger Labs](https://portswigger.net/web-security/all-labs).
