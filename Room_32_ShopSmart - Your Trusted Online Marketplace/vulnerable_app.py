from flask import Flask, render_template_string, request, redirect, url_for
import xml.etree.ElementTree as ET

app = Flask(__name__)

# HTML template for the e-commerce homepage
home_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ShopSmart - Your Trusted Online Marketplace</title>
    <style>
        /* Styling to make the webpage attractive and professional */
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
        header { background-color: #2c3e50; padding: 20px; text-align: center; color: white; }
        nav { display: flex; justify-content: center; background-color: #34495e; }
        nav a { color: white; padding: 14px 20px; text-decoration: none; }
        nav a:hover { background-color: #2c3e50; }
        main { padding: 20px; }
        footer { background-color: #2c3e50; padding: 10px; text-align: center; color: white; position: fixed; bottom: 0; width: 100%; }
        .products { display: flex; flex-wrap: wrap; justify-content: space-around; }
        .product { background-color: white; border: 1px solid #ddd; border-radius: 5px; margin: 10px; padding: 10px; width: 200px; text-align: center; }
        .product img { max-width: 100%; border-bottom: 1px solid #ddd; margin-bottom: 10px; }
        .product h3 { font-size: 18px; margin: 10px 0; }
        .product p { color: #e74c3c; font-weight: bold; }
        .product button { background-color: #e67e22; color: white; border: none; padding: 10px; cursor: pointer; border-radius: 5px; }
        .product button:hover { background-color: #d35400; }
    </style>
</head>
<body>
    <header>
        <h1>ShopSmart</h1>
        <p>Your Trusted Online Marketplace</p>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/cart">My Cart</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <main>
        <h2>Featured Products</h2>
        <div class="products">
            <!-- Product 1 -->
            <div class="product">
                <img src="https://via.placeholder.com/150" alt="Wireless Headphones">
                <h3>Wireless Headphones</h3>
                <p>$59.99</p>
                <button onclick="addToCart('Wireless Headphones')">Add to Cart</button>
            </div>
            <!-- Product 2 -->
            <div class="product">
                <img src="https://via.placeholder.com/150" alt="Smart Watch">
                <h3>Smart Watch</h3>
                <p>$129.99</p>
                <button onclick="addToCart('Smart Watch')">Add to Cart</button>
            </div>
            <!-- Product 3 -->
            <div class="product">
                <img src="https://via.placeholder.com/150" alt="Bluetooth Speaker">
                <h3>Bluetooth Speaker</h3>
                <p>$39.99</p>
                <button onclick="addToCart('Bluetooth Speaker')">Add to Cart</button>
            </div>
            <!-- Product 4 -->
            <div class="product">
                <img src="https://via.placeholder.com/150" alt="E-Reader">
                <h3>E-Reader</h3>
                <p>$89.99</p>
                <button onclick="addToCart('E-Reader')">Add to Cart</button>
            </div>
        </div>
    </main>
    <footer>
        &copy; 2023 ShopSmart Inc. All rights reserved.
    </footer>
    <script>
        function addToCart(productName) {
            window.location.href = '/add_to_cart?product=' + encodeURIComponent(productName);
        }
    </script>
</body>
</html>
'''

# In-memory cart to store added products (for demonstration purposes)
user_cart = []

@app.route('/')
def home():
    return render_template_string(home_page_html)

@app.route('/add_to_cart', methods=['GET'])
def add_to_cart():
    product = request.args.get('product', '')
    # Simulate storing product data in XML format (introducing XXE vulnerability)
    xml_data = f'''
    <?xml version="1.0" encoding="UTF-8"?>
    <cart>
        <item>
            <name>{product}</name>
        </item>
    </cart>
    '''
    try:
        # Parsing XML data without disabling external entities (vulnerable to XXE)
        tree = ET.fromstring(xml_data)
        product_name = tree.find('.//name').text
        user_cart.append(product_name)
        return redirect(url_for('cart'))
    except ET.ParseError:
        return 'An error occurred while processing your request.', 400

@app.route('/cart')
def cart():
    cart_items = '<br>'.join(user_cart) if user_cart else 'Your cart is empty.'
    cart_page = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>My Cart - ShopSmart</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }}
            header {{ background-color: #2c3e50; padding: 20px; text-align: center; color: white; }}
            nav {{ display: flex; justify-content: center; background-color: #34495e; }}
            nav a {{ color: white; padding: 14px 20px; text-decoration: none; }}
            nav a:hover {{ background-color: #2c3e50; }}
            main {{ padding: 20px; }}
            footer {{ background-color: #2c3e50; padding: 10px; text-align: center; color: white; position: fixed; bottom: 0; width: 100%; }}
        </style>
    </head>
    <body>
        <header>
            <h1>ShopSmart - My Cart</h1>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/cart">My Cart</a>
            <a href="/contact">Contact Us</a>
        </nav>
        <main>
            <h2>Items in Your Cart:</h2>
            <p>{cart_items}</p>
        </main>
        <footer>
            &copy; 2023 ShopSmart Inc. All rights reserved.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(cart_page)

@app.route('/contact')
def contact():
    contact_page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Contact Us - ShopSmart</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }}
            header {{ background-color: #2c3e50; padding: 20px; text-align: center; color: white; }}
            nav {{ display: flex; justify-content: center; background-color: #34495e; }}
            nav a {{ color: white; padding: 14px 20px; text-decoration: none; }}
            nav a:hover {{ background-color: #2c3e50; }}
            main {{ padding: 20px; }}
            footer {{ background-color: #2c3e50; padding: 10px; text-align: center; color: white; position: fixed; bottom: 0; width: 100%; }}
            form {{ max-width: 600px; margin: auto; }}
            label {{ display: block; margin: 15px 0 5px; }}
            input, textarea {{ width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 5px; }}
            button {{ background-color: #e67e22; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 5px; }}
            button:hover {{ background-color: #d35400; }}
        </style>
    </head>
    <body>
        <header>
            <h1>Contact Us - ShopSmart</h1>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/cart">My Cart</a>
            <a href="/contact">Contact Us</a>
        </nav>
        <main>
            <h2>We'd love to hear from you!</h2>
            <form action="#" method="post">
                <label for="name">Your Name:</label>
                <input type="text" id="name" name="name">
                <label for="email">Your Email:</label>
                <input type="email" id="email" name="email">
                <label for="message">Your Message:</label>
                <textarea id="message" name="message" rows="5"></textarea>
                <button type="submit">Send Message</button>
            </form>
        </main>
        <footer>
            &copy; 2023 ShopSmart Inc. All rights reserved.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(contact_page)

if __name__ == '__main__':
    app.run(debug=True)