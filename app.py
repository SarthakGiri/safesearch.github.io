from flask import Flask, render_template, request, redirect, url_for
import re
import requests
import json

app = Flask(__name__)

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp|https)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return regex.match(url) is not None

def check_website(url):
    api_key = "AIzaSyB2ZFJaKCjuNamvUfoY0oaZn_s_wvAFbNA"
    api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    headers = {'Content-Type': 'application/json'}
    threat_info = {'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                                  'platformTypes': ['ANY_PLATFORM'],
                                  'threatEntryTypes': ['URL'],
                                  'threatEntries': [{'url': url}]}}
    params = {'key': api_key}
    response = requests.post(api_url, headers=headers, params=params, data=json.dumps(threat_info))
    if response.status_code == 200 and 'matches' in response.json():
        return False
    else:
        return True

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        if is_valid_url(url):
            is_safe = check_website(url)
            if is_safe:
                return render_template('result.html', is_safe=is_safe, message="URL: " + url)
            else:
                return render_template('result.html', is_safe=is_safe, message="URL: " + url)
        else:
            return render_template('index.html', message="Invalid URL. Please enter a valid URL.")
    return render_template('index.html', message=None)


if __name__ == '__main__':
    app.run(debug=True)
