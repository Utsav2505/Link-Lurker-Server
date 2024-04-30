# importing modules
from flask import Flask, render_template, request, jsonify
import whois
from datetime import datetime
import requests
from flask_cors import CORS 
from openphish import run
import csv
import pickle
import pandas as pd
import json
import os
import time

app = Flask(__name__)
CORS(app)

# metrics
domain_analysis = 0
url_reporting = 0
starting_time = time.time()

# domain analysis
def analyze_domain_and_security(url):
    try:
        # Extract domain from the URL
        domain = url.split('//')[-1].split('/')[0]
        
        # WHOIS lookup
        domain_info = whois.whois(domain)

        # Check the creation date of the domain
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Current date
        current_date = datetime.now()
        
        # Calculate the age of the domain in days
        age_in_days = (current_date - creation_date).days

        # Send an HTTP HEAD request to fetch headers only
        response = requests.head(url)

        result = {
            "domain": domain,
            "creation_date": str(creation_date),
            "domain_age_in_days": age_in_days,
            "uses_https": response.url.startswith("https://"),
            "has_csp_header": 'YES' if 'Content-Security-Policy' in response.headers else 'NO',
            "has_hsts": 'YES' if 'Strict-Transport-Security' in response.headers else 'NO',
            "has_x_content_type_options": 'YES' if 'X-Content-Type-Options' in response.headers else 'NO',
            "has_x_frame_options": 'YES' if 'X-Frame-Options' in response.headers else 'NO',
        }
        # domain_analysis += 1
        return result

    except Exception as e:
        return {"error": str(e)}

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()

    if 'url' not in data:
        return jsonify({"error": "Please provide a 'url' parameter in the request body."}), 400

    url_to_analyze = data['url']
    result = analyze_domain_and_security(url_to_analyze)

    return jsonify(result)

# database check
def search_url_in_csv(target_url):
    csv_file = 'phishing_data.csv'
    with open(csv_file, 'r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if target_url in row:
                return True
    
    return False
@app.route('/database_search', methods=['POST'])
def database_search():
    data = request.get_json()

    if 'url' not in data:
        return jsonify({"error": "Please provide a 'url' parameter in the request body."}), 400
    url_to_analyze = data['url']
    result = search_url_in_csv(url_to_analyze)
    return jsonify({"found_in_database": result})

# URL screening
loaded_model = pickle.load(open('phishing.pkl', 'rb'))
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()

    if 'url' not in data:
        return jsonify({"error": "Please provide a 'url' parameter in the request body."}), 400
    url_to_analyze = data['url']
    result = loaded_model.predict([url_to_analyze])
    return jsonify({"found_in_database": result})

# URL reporting
def appendURL(url):
    try:
        df = pd.read_csv('phishing_data.csv')
    except FileNotFoundError:
        df = pd.DataFrame(columns=['Phishing URL'])
    new_data = pd.DataFrame({'Phishing URL': [url]})
    df = pd.concat([df, new_data]).drop_duplicates().reset_index(drop=True)
    df.to_csv('phishing_data.csv', index=False)
    # url_reporting += 1

@app.route('/report', methods=['POST'])
def report():
    data = request.get_json()

    if 'url' not in data:
        return jsonify({"error": "Please provide a 'url' parameter in the request body."}), 400
    url_to_report = data['url']
    appendURL(url_to_report)
    return jsonify({"success": True})

# scraping urls
@app.route('/scrape', methods=['GET'])
def scrape():
    run()
    return jsonify({"success": True})

# server logging
def append_logs():
    log_data = {}
    if os.path.exists('logs.json'):
        with open('logs.json', 'r') as log_file:
            log_data = json.load(log_file)
    server_uptime = starting_time-time.time()
    log_dict = {"domain_analysis":domain_analysis, "url_reporting": url_reporting, "server_uptime": server_uptime}
    log_data.update(log_dict)
    with open('logs.json', 'w') as log_file:
        json.dump(log_data, log_file, indent=4)
    
@app.route('/log', methods=['GET'])
def log():
    append_logs()
    with open('logs.json', 'r') as log_file:
        log_data = json.load(log_file)
    return jsonify(log_data)

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Welcome to the Phishy API. Use the following endpoints for different functionalities:",
        "endpoints": {
            "/analyze": "Analyze the domain and security features of a given URL.",
            "/database_search": "Check for a URL in the database of known phishing URLs.",
            "/predict": "Predict whether a given URL is a phishing URL or not.",
            "/report": "Report a URL as a phishing URL.",
            "/scrape": "Scrape the OpenPhish website for new phishing URLs.",
            "/log": "Get the server logs."
        }
    })

# run server
if __name__ == '__main__':
    app.run(debug=True, port=5000)