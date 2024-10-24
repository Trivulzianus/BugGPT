# Exploitation and Mitigation of DOM-Based XSS in Flask Web App

## Exploitation

The given Flask web application is vulnerable to a DOM-based Cross-Site Scripting (XSS) attack. DOM-based XSS occurs when user-supplied data is used in the client-side script without proper sanitization or escaping, leading to the execution of arbitrary scripts on the client's browser. 

### Steps to Exploit:

1. **Identify the Vulnerability Point**:  
   The vulnerability lies in the JavaScript code:
   ```javascript
   let reflection = "<div>The Aether reflects the rune: " + rune + "</div>";
   document.body.insertAdjacentHTML('beforeend', reflection);
   ```
   Here, the user input from the text field with id `rune` is directly concatenated into an HTML string and inserted into the DOM using `insertAdjacentHTML`, which processes the string as HTML markup.

2. **Crafting a Malicious Input**:  
   By entering a malicious string into the input field, it can break out of the context and execute arbitrary JavaScript. Example:
   ```html
   <script>alert('XSS Attack!');</script>
   ```
   When this input is entered in the "rune" field and the button is clicked, it will append the script tag to the DOM, triggering the `alert` function.

### Demonstration:

To manually trigger an XSS attack, enter the following payload in the rune input field:
```javascript
"><script>alert('XSS Attack!')</script>
```

## Mitigation

To prevent DOM-based XSS, ensure all user inputs are properly sanitized or escaped before being added to the DOM.

### Best Practices for Mitigation:

1. **Escape HTML**: Always escape user input before inserting it into the HTML context. This prevents HTML tags from being interpreted as markup. JavaScript libraries like DOMPurify can be used for safe HTML sanitization.

2. **Use a Safe Insertion Method**: Instead of using `insertAdjacentHTML` or similar methods that directly inject HTML, use methods such as:
    ```javascript
    let safeRune = document.createTextNode(rune);
    let reflectionContainer = document.createElement('div');
    reflectionContainer.appendChild(safeRune);
    document.body.appendChild(reflectionContainer);
    ```
   This ensures that any input is treated as plain text, neutralizing potential scripts.

3. **Content Security Policy (CSP)**: Implement CSP headers to restrict the sources of executable scripts. Although not a direct solution for every scenario, CSP adds a layer of defense in mitigating certain types of XSS attacks.

4. **Input Validation**: On the server side, validate inputs to ensure they conform to expected patterns. This won't directly prevent DOM-based XSS, but it serves as an additional layer of security.

5. **Regular Security Audits and Testing**: Regularly test the application for XSS vulnerabilities and other security flaws using automated tools and manual penetration testing.

### Example Resolution:

Modify the client-side code as follows:
```javascript
questButton.addEventListener('click', function() {
    let rune = runeInput.value;
    if (rune) {
        let safeRune = document.createTextNode("The Aether reflects the rune: " + rune);
        let reflectionContainer = document.createElement('div');
        reflectionContainer.appendChild(safeRune);
        document.body.appendChild(reflectionContainer);
    }
});
```

By adopting these practices, developers can significantly reduce the risk of XSS vulnerabilities and enhance the security of web applications.