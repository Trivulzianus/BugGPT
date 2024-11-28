from flask import Flask, request, render_template_string, redirect, url_for
import requests
import re

app = Flask(__name__)

# Sample users data
users = [
    {'name': 'Alice', 'status': 'Loving the new social network!', 'image': 'https://via.placeholder.com/150'},
    {'name': 'Bob', 'status': 'Just had the best coffee ever!', 'image': 'https://via.placeholder.com/150'},
    {'name': 'Charlie', 'status': 'Anyone up for a game tonight?', 'image': 'https://via.placeholder.com/150'},
]

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>FriendZone - Connect with your friends</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 0; }
            .navbar { background-color: #4267B2; padding: 15px; color: white; }
            .navbar h1 { margin: 0; display: inline-block; }
            .content { padding: 20px; }
            .post { background-color: white; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
            .post img { float: left; margin-right: 15px; border-radius: 50%; }
            .post h2 { margin: 0; }
            .post p { clear: both; }
            .footer { background-color: #4267B2; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%; }
            .upload { background-color: white; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
            .upload input[type=text] { width: 80%; padding: 10px; }
            .upload input[type=submit] { padding: 10px; }
        </style>
    </head>
    <body>
        <div class="navbar">
            <h1>FriendZone</h1>
        </div>
        <div class="content">
            <div class="upload">
                <h2>Share an interesting website with your friends!</h2>
                <form action="/share" method="get">
                    <input type="text" name="url" placeholder="Enter website URL">
                    <input type="submit" value="Share">
                </form>
            </div>
            {% for user in users %}
            <div class="post">
                <img src="{{ user.image }}" alt="{{ user.name }}" width="75" height="75">
                <h2>{{ user.name }}</h2>
                <p>{{ user.status }}</p>
            </div>
            {% endfor %}
        </div>
        <div class="footer">
            &copy; 2023 FriendZone. All rights reserved.
        </div>
    </body>
    </html>
    ''', users=users)

@app.route('/share')
def share():
    url = request.args.get('url', '')
    if url:
        # Simple regex to check if the URL is valid (this can be bypassed)
        if re.match(r'^https?://[\w\-\.]+(\.\w+)+(\/\S*)?$', url):
            try:
                # Fetch the content of the URL
                resp = requests.get(url, timeout=5)
                content = resp.text
                # Extract the title of the page
                title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
                title = title_match.group(1) if title_match else 'No Title Found'
                return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Shared Content - FriendZone</title>
                    <style>
                        body { font-family: Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 0; }
                        .navbar { background-color: #4267B2; padding: 15px; color: white; }
                        .navbar h1 { margin: 0; display: inline-block; }
                        .content { padding: 20px; }
                        .preview { background-color: white; padding: 15px; border-radius: 5px; }
                        .footer { background-color: #4267B2; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%; }
                    </style>
                </head>
                <body>
                    <div class="navbar">
                        <h1>FriendZone</h1>
                    </div>
                    <div class="content">
                        <div class="preview">
                            <h2>{{ title }}</h2>
                            <p>Content fetched from: {{ url }}</p>
                        </div>
                    </div>
                    <div class="footer">
                        &copy; 2023 FriendZone. All rights reserved.
                    </div>
                </body>
                </html>
                ''', title=title, url=url)
            except Exception as e:
                return f"Error fetching the URL: {str(e)}"
        else:
            return "Invalid URL format!"
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)