### Exploitation Explanation

The vulnerability found in the provided Flask web application is an **Insecure Direct Object Reference (IDOR)**. In this scenario, an attacker can exploit the URL parameter directly to access sensitive information without proper authorization. 

#### Steps to Exploit:
1. Access the web application home page, which suggests a link to a user's profile: `/user/1`.
2. The URL suggests that the `user_id` is a sequential number.
3. By manually changing the `user_id` in the URL, for example `/user/2` or `/user/3`, the attacker can directly access other users' sensitive data.

This vulnerability arises because there is no authentication or authorization check to ensure that a user is allowed to access the data associated with a specific `user_id`.

### Mitigation Strategies

To prevent IDOR vulnerabilities, developers should implement proper access controls. Here are some best practices:

1. **Authentication and Authorization:**
   Ensure that users are authenticated, and implement authorization checks to verify that the authenticated user has permission to access a particular resource. 

   ```python
   from flask import session
   # Modify user_profile route
   @app.route('/user/<int:user_id>')
   def user_profile(user_id):
       # Ensure user is logged in
       if not 'logged_in_user_id' in session:
           return redirect(url_for('login'))
       # Check if logged in user is authorized to view this profile
       if session['logged_in_user_id'] == user_id:
           user_info = mock_data.get(user_id)
           return render_template_string(PROFILE_PAGE_HTML, user=user_info)
       else:
           return redirect(url_for('home'))
   ```

2. **Avoid Direct Access to Object Identifiers:**
   Instead of using sequential numbers or identifiers that can easily be guessed, consider using UUIDs or other non-guessable identifiers.

3. **Implement Role-Based Access Control (RBAC):**
   Use roles and permissions to manage who can access what resources. This layer can help enforce stricter access control.

4. **Audit Logs:**
   Implement logging of access attempts to sensitive information. Logs can help detect unauthorized access attempts.

5. **Input Validation and Binding:**
   Validate user input and use parameterized queries to prevent unintended consequences of user input. Though not strictly relevant here, this practice can prevent other vulnerabilities like SQL injection.

6. **Secure Default Policy:**
   Adopt a default-deny policy where permissions need to be expressly given, instead of default-allow.

Here's an example implementation adding basic authentication and making sure users can only view their own profile:

```python
from flask import Flask, session, render_template_string, redirect, url_for

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Used for session management

# Sample user sessions
user_sessions = {
    "alice": 1,
    "bob": 2,
    "charlie": 3
}

# Mock login to simulate user authentication
@app.route('/login/<username>')
def login(username):
    if username in user_sessions:
        session['logged_in_user_id'] = user_sessions[username]
        return redirect(url_for('user_profile', user_id=user_sessions[username]))
    return "User not found", 404

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    if not 'logged_in_user_id' in session:
        return redirect(url_for('login', username='alice'))
    if session['logged_in_user_id'] != user_id:
        return "Unauthorized access", 403
    
    user_info = mock_data.get(user_id)
    return render_template_string(PROFILE_PAGE_HTML, user=user_info)
```

By implementing these strategies, you can significantly reduce the risk of IDOR vulnerabilities in your application.