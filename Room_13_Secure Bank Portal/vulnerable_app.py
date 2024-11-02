from flask import Flask, request, render_template_string

app = Flask(__name__)

main_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #eef2f5; margin: 0; }
        .header { background-color: #004080; color: white; padding: 20px; text-align: center; }
        .container { padding: 50px; }
        .news-form { background-color: #fff; padding: 20px; border-radius: 5px; }
        input[type="text"] { width: 80%; padding: 10px; margin: 10px 0; }
        input[type="submit"] { padding: 10px 20px; background-color: #004080; color: white; border: none; cursor: pointer; }
        footer { background-color: #004080; color: white; text-align: center; padding: 10px 0; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to Secure Bank</h1>
        <p>Your trusted partner in financial growth</p>
    </div>
    <div class="container">
        <div class="news-form">
            <h2>Market Watcher</h2>
            <p>Stay updated with the latest financial news. Enter a news article URL to preview:</p>
            <form action="/preview" method="get">
                <input type="text" name="url" placeholder="https://example.com/news-article">
                <br>
                <input type="submit" value="Preview Article">
            </form>
        </div>
    </div>
    <footer>
        &copy; 2023 Secure Bank. All rights reserved.
    </footer>
</body>
</html>
'''

preview_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Article Preview - Secure Bank</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #eef2f5; margin: 0; }
        .header { background-color: #004080; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #fff; margin: 20px; border-radius: 5px; }
        a { text-decoration: none; color: #004080; }
        footer { background-color: #004080; color: white; text-align: center; padding: 10px 0; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Article Preview</h1>
    </div>
    <div class="content">
        {{ content | safe }}
    </div>
    <div style="text-align: center;">
        <a href="/">&#8592; Back to Home</a>
    </div>
    <footer>
        &copy; 2023 Secure Bank. All rights reserved.
    </footer>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(main_page)

@app.route('/preview')
def preview():
    url = request.args.get('url')
    if not url:
        return "Please provide a URL.", 400
    try:
        response = requests.get(url)
        content = response.text
        return render_template_string(preview_page, content=content)
    except Exception as e:
        return f"An error occurred: {e}", 500

if __name__ == '__main__':
    app.run(debug=Fals)