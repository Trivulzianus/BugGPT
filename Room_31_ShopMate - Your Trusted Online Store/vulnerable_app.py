from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Database setup
def init_db():
    if not os.path.exists('ecommerce.db'):
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
        ''')
        c.execute('''
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            order_details TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        conn.commit()
        conn.close()

def create_sample_data():
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES ('alice', 'password1')")
        c.execute("INSERT INTO users (username, password) VALUES ('bob', 'password2')")
        c.execute("INSERT INTO orders (user_id, order_details) VALUES (1, 'Order #1001: iPhone 14')")
        c.execute("INSERT INTO orders (user_id, order_details) VALUES (1, 'Order #1002: MacBook Pro')")
        c.execute("INSERT INTO orders (user_id, order_details) VALUES (2, 'Order #1003: Samsung Galaxy S22')")
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Data already exists
    conn.close()

init_db()
create_sample_data()

# Templates
base_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ShopMate - Your Trusted Online Store</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }}
        .header {{ background-color: #35424a; color: #ffffff; padding: 20px 0; text-align: center; }}
        .container {{ width: 80%; margin: auto; overflow: hidden; }}
        .navbar {{ overflow: hidden; background-color: #333; }}
        .navbar a {{ float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }}
        .navbar a:hover {{ background-color: #ddd; color: black; }}
        h1 {{ color: #35424a; }}
        .button {{ display: inline-block; padding: 10px 20px; font-size: 16px; cursor: pointer; text-align: center; text-decoration: none; outline: none; color: #fff; background-color: #5cb85c; border: none; border-radius: 15px; }}
        .button:hover {{ background-color: #4cae4c; }}
        .button:active {{ background-color: #4cae4c; transform: translateY(2px); }}
        .content {{ padding: 20px; background-color: #ffffff; margin-top: 20px; border-radius: 5px; }}
        .footer {{ background-color: #35424a; color: #ffffff; text-align: center; padding: 10px; margin-top: 20px; }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ShopMate</h1>
        <p>Your Trusted Online Store</p>
    </div>
    <div class="navbar">
        <div class="container">
            <a href="{{ url_for('index') }}">Home</a>
            {% if 'username' in session %}
                <a href="{{ url_for('view_orders') }}">My Orders</a>
                <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            {% endif %}
        </div>
    </div>
    <div class="container">
        <div class="content">
            {% block content %}{% endblock %}
        </div>
    </div>
    <div class="footer">
        <p>&copy; 2023 ShopMate. All rights reserved.</p>
    </div>
</body>
</html>
'''

index_template = '''
{% extends "base_template" %}
{% block content %}
    <h1>Welcome to ShopMate</h1>
    {% if 'username' in session %}
        <p>Hello, <strong>{{ session['username'] }}</strong>! Browse our latest products or check your orders.</p>
        <a class="button" href="{{ url_for('view_orders') }}">View Your Orders</a>
    {% else %}
        <p>Sign up now to experience the best online shopping!</p>
        <a class="button" href="{{ url_for('register') }}">Register</a>
        <a class="button" href="{{ url_for('login') }}">Login</a>
    {% endif %}
{% endblock %}
'''

register_template = '''
{% extends "base_template" %}
{% block content %}
    <h1>Create an Account</h1>
    <form method="post">
        <p><label>Username:</label><br><input name="username" required></p>
        <p><label>Password:</label><br><input name="password" type="password" required></p>
        <p><input class="button" type="submit" value="Register"></p>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
    </form>
{% endblock %}
'''

login_template = '''
{% extends "base_template" %}
{% block content %}
    <h1>Account Login</h1>
    <form method="post">
        <p><label>Username:</label><br><input name="username" required></p>
        <p><label>Password:</label><br><input name="password" type="password" required></p>
        <p><input class="button" type="submit" value="Login"></p>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
    </form>
{% endblock %}
'''

orders_template = '''
{% extends "base_template" %}
{% block content %}
    <h1>Your Orders</h1>
    <ul>
    {% for order in orders %}
        <li><a href="{{ url_for('view_order_details', order_id=order[0]) }}">Order {{ order[0] }}</a></li>
    {% endfor %}
    </ul>
{% endblock %}
'''

order_details_template = '''
{% extends "base_template" %}
{% block content %}
    <h1>Order Details</h1>
    <p>{{ order_details }}</p>
    <a class="button" href="{{ url_for('view_orders') }}">Back to Orders</a>
{% endblock %}
'''

error_template = '''
{% extends "base_template" %}
{% block content %}
    <h1>Error</h1>
    <p class="error">{{ message }}</p>
    <a class="button" href="{{ url_for('index') }}">Return Home</a>
{% endblock %}
'''

# Routes
@app.route('/')
def index():
    return render_template_string(index_template, base_template=base_template)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            error = "Username already exists!"
    return render_template_string(register_template, base_template=base_template, error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            error = "Invalid credentials!"
    return render_template_string(login_template, base_template=base_template, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/orders')
def view_orders():
    if 'username' in session:
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        user_id = session['user_id']
        c.execute("SELECT id, order_details FROM orders WHERE user_id=?", (user_id,))
        orders = c.fetchall()
        conn.close()
        return render_template_string(orders_template, base_template=base_template, orders=orders)
    else:
        return redirect(url_for('login'))

@app.route('/order_details')
def view_order_details():
    if 'username' in session:
        order_id = request.args.get('order_id')
        if not order_id:
            return render_template_string(error_template, base_template=base_template, message="Order ID is missing.")
        conn = sqlite3.connect('ecommerce.db')
        c = conn.cursor()
        # Vulnerability: No check if the order belongs to the logged-in user
        c.execute("SELECT order_details FROM orders WHERE id=?", (order_id,))
        order = c.fetchone()
        conn.close()
        if order:
            return render_template_string(order_details_template, base_template=base_template, order_details=order[0])
        else:
            return render_template_string(error_template, base_template=base_template, message="Order not found.")
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)