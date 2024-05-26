from flask import Flask, request, render_template_string
import pickle
import numpy as np
import re

# Load the trained model (replace with your model loading logic)
model = pickle.load(open("models/phishing_model.pkl", "rb"))  # Assuming model saved as phishing_model.pkl

# Define blacklist (replace with your list of known phishing URLs)
BLACKLIST_URLS = [
    "http://secure-your-account.com/login",
    "https://verify-your-account.net/",
    "http://update-your-information.org/login.php",
    "https://secure-transaction-login.xyz/",
    "http://account-confirmation.net/login.php",
    "https://login-verification-code.com/",
    "http://important-notification.com/login",
    "https://account-security-check.org/login.php",
    "http://user-verification-center.net/",
    "https://login-secure-authentication.com/",
    # ... (add more URLs)
]

# Function to extract features from the URL
def extract_features(url):
    features = []

    # Feature 1: Length of the URL
    features.append(len(url))

    # Feature 2: Presence of HTTPS
    features.append(1 if url.startswith("https://") else 0)

    # Feature 3: Presence of redirects
    features.append(1 if "redirect" in url.lower() else 0)

    # Feature 4: Presence of suspicious keywords
    suspicious_keywords = [
        'nobell', 'it', 'ffb', 'd', 'dca', 'cce', 'f', 'login', 'SkyPe', 'com', 'en', 'cgi', 'bin', 'verification', 'login', 'ffb', 'd', 'dca', 'cce', 'f', 'index', 'php', 'cmd', 'profile', 'ach', 'outdated', 'page', 'tmpl', 'p', 'gen', 'failed', 'to', 'load', 'nav', 'login', 'access'
    ]
    features.append(sum(word in url.lower() for word in suspicious_keywords))

    # Feature 5: Subdomain length
    subdomains = url.split('.')[:-2]
    subdomain_length = sum(len(subdomain) for subdomain in subdomains)
    features.append(subdomain_length)

    # Feature 6: Presence of IP address in URL
    features.append(1 if re.findall(r"\d+\.\d+\.\d+\.\d+", url) else 0)

    # Feature 7: Presence of hyphen in domain name
    features.append(1 if '-' in url.split('://')[1].split('.')[0] else 0)

    # Feature 8: Presence of urgency words
    urgency_words = ["urgent", "immediate", "verify now", "important"]
    features.append(sum(word in url.lower() for word in urgency_words))

    # Feature 9: Presence of suspicious substrings (optional)
    suspicious_substrings = ["login", "account", "security", "update", "confirmation"]
    features.append(sum(substring in url.lower() for substring in suspicious_substrings))

    # Handle potential mismatch in feature count
    if len(features) > 31:
        features = features[:31]  # Truncate to expected number
    elif len(features) < 31:
        features.extend([0] * (31 - len(features)))  # Pad with zeros

    return np.array(features).reshape(1, -1)

# Function to check if URL is likely phishing
def check_phishing(url):
    # Check if URL is in blacklist
    if url in BLACKLIST_URLS:
        return "Phishing"  # URL found in blacklist
    
    # Extract features from URL
    features = extract_features(url)
    
    # Predict using trained model
    prediction = model.predict(features)[0]
    
    if prediction == 1:
        return "Phishing"  # Model predicts phishing
    else:
        return "Legitimate"  # Model predicts legitimate

# Flask app setup
app = Flask(__name__)

# Route for home page
@app.route('/')
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishing Detection</title>
    </head>
    <body>
        <h1>Phishing Detection</h1>
        <form action="/check_url" method="post">
            <label for="url">Enter URL:</label>
            <input type="text" id="url" name="url">
            <button type="submit">Check</button>
        </form>
        {% if error %}
            <p>{{ error }}</p>
        {% endif %}
        {% if result %}
            <p>The URL {{ url }} is {{ result }}.</p>
        {% endif %}
    </body>
    </html>
    """)

# Route for checking URL
@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form.get('url')

    if not url:
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Phishing Detection</title>
        </head>
        <body>
            <h1>Phishing Detection</h1>
            <form action="/check_url" method="post">
                <label for="url">Enter URL:</label>
                <input type="text" id="url" name="url">
                <button type="submit">Check</button>
            </form>
            <p>No URL provided.</p>
        </body>
        </html>
        """)

    result = check_phishing(url)
    
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishing Detection</title>
    </head>
    <body>
        <h1>Phishing Detection</h1>
        <form action="/check_url" method="post">
            <label for="url">Enter URL:</label>
            <input type="text" id="url" name="url">
            <button type="submit">Check</button>
        </form>
        <p>The URL {{ url }} is {{ result }}.</p>
    </body>
    </html>
    """, result=result, url=url)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
