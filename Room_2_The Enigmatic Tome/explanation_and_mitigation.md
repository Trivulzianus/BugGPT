## Exploitation

The web app presented contains a classic SQL Injection vulnerability within the query for searching books by title or author. The vulnerability arises from the direct inclusion of user input (`search_term`) into the SQL query string without proper sanitization or parameterization, using:

```python
query = f"SELECT * FROM library WHERE title LIKE '%{search_term}%' OR author LIKE '%{search_term}%'"
```

An attacker can exploit this vulnerability by crafting a malicious input that alters the structure of the SQL query. For example, an attacker might input:

```
' OR '1'='1
```

When placed into the query, it transforms into:

```sql
SELECT * FROM library WHERE title LIKE '%' OR '1'='1'%' OR author LIKE '%' OR '1'='1'%' 
```

This query will always evaluate to true and returns all records in the database, potentially exposing sensitive information like the secrets column.

## Mitigation Recommendations

To safeguard the application against SQL Injection, consider the following best practices:

### 1. **Use Parameterized Queries**

Parameterized queries help ensure that user input is treated as data, not executable code, thus preventing SQL Injection attacks. Update the `home` function as follows:

```python
query = "SELECT * FROM library WHERE title LIKE ? OR author LIKE ?"
cursor.execute(query, (f"%{search_term}%", f"%{search_term}%"))
```

### 2. **Use an ORM**

Consider using an Object Relational Mapper (ORM) like SQLAlchemy, which abstracts away SQL and provides a programmatic way to interact with the database. ORM tools inherently provide protection against SQL Injection attacks.

### 3. **Input Validation and Sanitization**

While parameterized queries address the core issue, always validate and sanitize input to ensure it matches expected patterns, lengths, and types.

### 4. **Use a Web Application Firewall (WAF)**

Deploy a Web Application Firewall to help monitor and filter out malicious input attempting to exploit vulnerabilities.

### 5. **Regularly Update and Patch Dependencies**

Keep all libraries and dependencies up to date to minimize exposure through known vulnerabilities.

## Conclusion

By adopting parameterized queries, using an ORM, validating inputs, employing a WAF, and keeping dependencies updated, developers can significantly reduce the risk of SQL Injection vulnerabilities and ensure a robust defense of their web applications.