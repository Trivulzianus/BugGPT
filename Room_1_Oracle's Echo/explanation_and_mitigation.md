```markdown
# SQL Injection Vulnerability in Python Flask App

## Overview of Vulnerability

The provided web application is utilizing a SQL query that directly includes user-submitted data without proper sanitation. This creates a risk of SQL Injection, specifically a time-based SQL Injection attack. Here's how the exploitation would work and how developers can implement best practices to mitigate such vulnerabilities.

### Exploitation Steps

1. **Understanding the Vulnerability**:
   The application directly concatenates `input_param` into the SQL query:
   ```python
   result = query_db(f"SELECT * FROM secrets WHERE id = {input_param}")
   ```
   This is vulnerable to SQL Injection where an attacker can manipulate the `input_param` to alter the behavior of the SQL query executed on the database.

2. **Performing a Time-Based SQL Injection**:
   Since there is an intentional delay introduced in the querying function, an attacker can use this to infer values:
   - By submitting a payload such as `1 OR 1=1 --`, the attacker can retrieve all rows instead of one, revealing the stored secret.
   - By submitting a payload like `1 AND (SELECT 1 FROM sqlite_master WHERE type='table' AND name='secrets')=1 WAITFOR DELAY '0:0:5' --`, an attcker can infer existence and inspect tables and columns.

### Exploitation Example

To demonstrate, an attacker might submit `1;; --` or other SQL time delay functions to identify if/where the injection occurs. However, SQLite does not support `WAITFOR` so this may need to be adapted for DBMS specific commands.

## Mitigation Strategies

To prevent SQL Injection vulnerabilities, developers should adhere to the following best practices:

### 1. **Use Parameterized Queries**
   - Instead of string concatenation, use parameterized queries:
   ```python
   result = query_db("SELECT * FROM secrets WHERE id = ?", (input_param,))
   ```
   Using the `?` placeholder or equivalent in other databases ensures the input is correctly sanitized.

### 2. **Validate and Sanitize Inputs**
   - Ensure all incoming data is validated and sanitized. In this case, ids should be integers, so:
   ```python
   try:
       input_param = int(request.form.get('query_input', ''))
   except ValueError:
       return "Invalid input"
   ```

### 3. **Use ORM (Object-Relational Mapping) Libraries**
   - Libraries such as SQLAlchemy adhere to best practices inherently, abstracting SQL queries to a higher level:
   ```python
   from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData
   # Example ORM setup, bypasses direct SQL string building
   ```

### 4. **Limit SQL Errors Returning to the Client**
   - Implement logging and error handling mechanisms to log errors internally without exposing them to end-users.

### 5. **Regular Security Reviews**
   - Maintain regular code audits and reviews to capture potential injection points or insecure coding practices.

Following these strategies ensures a robust defense against SQL injection attacks in web applications.

## Security Enhancement Steps

- **Implement Content Security Policy (CSP)** for XSS mitigation.
- Regularly update dependencies to patch known vulnerabilities.
- Consider using security libraries such as `Flask-Security` or deploying WAFs (Web Application Firewalls) for additional protection.

By adopting these best practices, developers can reduce the risk of SQL Injection attacks and related vulnerabilities in web applications.
```