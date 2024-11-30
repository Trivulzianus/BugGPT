from flask import Flask, render_template_string, request, redirect, url_for
import sqlite3
import re

app = Flask(__name__)

# Initialize the database with some dummy data
def init_db():
    if not os.path.exists('ecommerce.db'):
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # Create products table
        cursor.execute('''
            CREATE TABLE products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL
            )
        ''')
        # Insert sample products
        cursor.executemany('''
            INSERT INTO products (name, description, price) VALUES (?, ?, ?)
        ''', [
            ('Smartphone', 'Latest model smartphone with advanced features', 799.99),
            ('Laptop', 'High-performance laptop for professionals', 1199.99),
            ('Headphones', 'Noise-cancelling over-ear headphones', 199.99),
            ('Smartwatch', 'Wearable smartwatch with health tracking', 299.99),
            ('Camera', 'Digital camera with high resolution', 499.99)
        ])
        conn.commit()
        conn.close()

init_db()

@app.route('/')
def index():
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products')
    products = cursor.fetchall()
    conn.close()
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ShopEasy - Your One-Stop Online Store</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            header { background-color: #333; padding: 20px; color: white; text-align: center; }
            nav a { margin: 0 15px; color: white; text-decoration: none; }
            .container { padding: 20px; }
            .product { border: 1px solid #ccc; padding: 10px; margin: 10px; display: inline-block; width: 200px; vertical-align: top; }
            .product img { width: 100%; }
            .product-name { font-weight: bold; }
            .product-price { color: green; }
            footer { background-color: #333; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <header>
            <h1>ShopEasy</h1>
            <nav>
                <a href="{{ url_for('index') }}">Home</a>
                <a href="{{ url_for('search') }}">Search</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            </nav>
        </header>
        <div class="container">
            <h2>Featured Products</h2>
            {% for product in products %}
            <div class="product">
                <img src="https://via.placeholder.com/200x150" alt="{{ product[1] }}">
                <p class="product-name">{{ product[1] }}</p>
                <p class="product-price">${{ product[3] }}</p>
                <p><a href="/product/{{ product[0] }}">View Details</a></p>
            </div>
            {% endfor %}
        </div>
        <footer>
            &copy; 2023 ShopEasy. All rights reserved.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html, products=products)

@app.route('/product/<int:product_id>')
def product_details(product_id):
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    conn.close()
    if not product:
        return 'Product not found', 404
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ product[1] }} - ShopEasy</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            header { background-color: #333; padding: 20px; color: white; text-align: center; }
            nav a { margin: 0 15px; color: white; text-decoration: none; }
            .container { padding: 20px; }
            footer { background-color: #333; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <header>
            <h1>ShopEasy</h1>
            <nav>
                <a href="{{ url_for('index') }}">Home</a>
                <a href="{{ url_for('search') }}">Search</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            </nav>
        </header>
        <div class="container">
            <h2>{{ product[1] }}</h2>
            <img src="https://via.placeholder.com/400x300" alt="{{ product[1] }}">
            <p>{{ product[2] }}</p>
            <p class="product-price"><strong>Price:</strong> ${{ product[3] }}</p>
        </div>
        <footer>
            &copy; 2023 ShopEasy. All rights reserved.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html, product=product)

@app.route('/search', methods=['GET', 'POST'])
def search():
    results = []
    query = ''
    if request.method == 'POST':
        query = request.form['query']
        # Intentional complex logic with vulnerability
        # Naive protection against SQL injection
        sanitized_query = re.sub(r'[^a-zA-Z0-9 ]', '', query)
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        # Vulnerable SQL query construction
        sql = f"SELECT * FROM products WHERE name LIKE '%{sanitized_query}%'"
        cursor.execute(sql)
        results = cursor.fetchall()
        conn.close()
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search - ShopEasy</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            header { background-color: #333; padding: 20px; color: white; text-align: center; }
            nav a { margin: 0 15px; color: white; text-decoration: none; }
            .container { padding: 20px; }
            .product { border: 1px solid #ccc; padding: 10px; margin: 10px; display: inline-block; width: 200px; vertical-align: top; }
            .product img { width: 100%; }
            .product-name { font-weight: bold; }
            .product-price { color: green; }
            footer { background-color: #333; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%; }
            form { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <header>
            <h1>ShopEasy</h1>
            <nav>
                <a href="{{ url_for('index') }}">Home</a>
                <a href="{{ url_for('search') }}">Search</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            </nav>
        </header>
        <div class="container">
            <h2>Search Products</h2>
            <form method="post">
                <input type="text" name="query" value="{{ query }}" placeholder="Search for products..." required>
                <input type="submit" value="Search">
            </form>
            {% if results %}
                <h3>Search Results:</h3>
                {% for product in results %}
                <div class="product">
                    <img src="https://via.placeholder.com/200x150" alt="{{ product[1] }}">
                    <p class="product-name">{{ product[1] }}</p>
                    <p class="product-price">${{ product[3] }}</p>
                    <p><a href="/product/{{ product[0] }}">View Details</a></p>
                </div>
                {% endfor %}
            {% elif query %}
                <p>No products found matching "{{ query }}".</p>
            {% endif %}
        </div>
        <footer>
            &copy; 2023 ShopEasy. All rights reserved.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html, results=results, query=query)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Intentional flawed sanitization
        username = re.sub(r'[^\w]', '', username)
        password = re.sub(r'[^\w]', '', password)
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        # Vulnerable SQL query
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(sql)
        user = cursor.fetchone()
        conn.close()
        if user:
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password.'
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - ShopEasy</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            header { background-color: #333; padding: 20px; color: white; text-align: center; }
            nav a { margin: 0 15px; color: white; text-decoration: none; }
            .container { padding: 20px; }
            form { max-width: 300px; margin: 0 auto; }
            input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 5px 0; }
            input[type=submit] { padding: 10px; width: 100%; background-color: #333; color: white; border: none; }
            .error { color: red; }
            footer { background-color: #333; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <header>
            <h1>ShopEasy</h1>
            <nav>
                <a href="{{ url_for('index') }}">Home</a>
                <a href="{{ url_for('search') }}">Search</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            </nav>
        </header>
        <div class="container">
            <h2>Login</h2>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="submit" value="Login">
            </form>
        </div>
        <footer>
            &copy; 2023 ShopEasy. All rights reserved.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Simple input validation
        if not username or not password:
            error = 'Please provide both username and password.'
        else:
            conn = sqlite3.connect('ecommerce.db')
            cursor = conn.cursor()
            try:
                # Vulnerable SQL query
                sql = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
                cursor.execute(sql)
                conn.commit()
                conn.close()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Username already exists.'
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - ShopEasy</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            header { background-color: #333; padding: 20px; color: white; text-align: center; }
            nav a { margin: 0 15px; color: white; text-decoration: none; }
            .container { padding: 20px; }
            form { max-width: 300px; margin: 0 auto; }
            input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 5px 0; }
            input[type=submit] { padding: 10px; width: 100%; background-color: #333; color: white; border: none; }
            .error { color: red; }
            footer { background-color: #333; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <header>
            <h1>ShopEasy</h1>
            <nav>
                <a href="{{ url_for('index') }}">Home</a>
                <a href="{{ url_for('search') }}">Search</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            </nav>
        </header>
        <div class="container">
            <h2>Register</h2>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <input type="text" name="username" placeholder="Choose a username" required>
                <input type="password" name="password" placeholder="Choose a password" required>
                <input type="submit" value="Register">
            </form>
        </div>
        <footer>
            &copy; 2023 ShopEasy. All rights reserved.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html, error=error)

if __name__ == '__main__':
    app.run(debug=True)