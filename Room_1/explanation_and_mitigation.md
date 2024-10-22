```markdown
# Exploiting the Vulnerable Web App

The provided web application is vulnerable to an **Server-Side Request Forgery (SSRF)** attack. SSRF occurs when an attacker can manipulate the server to make requests to unintended resources, potentially leading to unauthorized access to internal systems, retrieval of sensitive information, or getting past firewalls.

## Exploitation Scenario

In the given application, a user can enter a URL, which the server then attempts to fetch using `requests.get(entered_url)`. Here's how exploitation can occur:

1. **Localhost Exploitation**: An attacker can supply `http://localhost:22` or similar URLs to try accessing internal services like SSH, available on the server.
2. **Metadata APIs**: Attackers might fetch metadata from cloud services like AWS by using URLs such as `http://169.254.169.254/latest/meta-data/`, which can leak sensitive data such as instance credentials.
3. **Internal Network Scanning**: An attacker can potentially scan internal network services by iterating over IP addresses without leaving the external network's boundaries.

By using these attack vectors, the server could inadvertently send requests to services that should not be accessible from outside or are not intended to be accessed by user inputs.

# Mitigation Strategies

To avoid such vulnerabilities in the future, developers should follow these best practices:

## 1. **Input Validation and Whitelisting**

- **Allow only certain domains**: Implement a whitelist of acceptable domains or patterns using techniques like regex or specific domain checking.
- **URL Parsing**: Thoroughly parse the URL to ensure that it doesn't resolve to internal IPs or any restricted resources.
  
```python
from urllib.parse import urlparse

def is_valid_url(url):
    try:
        parsed_url = urlparse(url)
        # Check against whitelist
        valid_domains = ['safe-domain.com', 'trusted-service.org']
        return parsed_url.hostname in valid_domains
    except Exception:
        return False

# Check the URL before making a request
if is_valid_url(entered_url):
    response = requests.get(entered_url)
else:
    result = "URL is not allowed."
```

## 2. **Network Controls**

- **Firewall Rules**: Implement strict firewall rules that limit outgoing requests from the application server to external or approved IP ranges only.
- **Internal Network Isolation**: Ensure that sensitive internal networks are not directly accessible from application servers, but instead isolated with layers of proxies or gateways.

## 3. **Use of Security Library Extensions**

Consider using security libraries such as the URL Driller for request auditing and enhanced filtering to prevent SSRF attacks. These libraries can provide additional protection by checking and auditing request paths.

## 4. **Implement Timeout and Rate Limiting**

- Limit the number of requests and implement timeouts to ensure that potentially harmful external requests don't bog down server resources.

```python
try:
    response = requests.get(entered_url, timeout=2)  # Set a timeout
except requests.RequestException as e:
    result = "An error occurred or request timed out: " + str(e)
```

By following these practices, developers can significantly reduce exposure to SSRF attacks and improve the overall security of web applications.
```