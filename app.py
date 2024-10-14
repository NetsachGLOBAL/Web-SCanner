from flask import Flask, request, render_template
import requests
from tags import tags
from sqltags import sqltags
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

def normalize_url(url):
    parsed_url = urlparse(url)
    
    # If no scheme (http/https) is provided, default to https
    if not parsed_url.scheme:
        url = f"https://{url}"
    
    # If the URL doesn't start with either http or https, assume https by default
    elif parsed_url.scheme not in ['http', 'https']:
        url = f"https://{parsed_url.netloc}{parsed_url.path}"
    
    return url

def detect_server_software(response):
    return response.headers.get("Server")

def detect_directory_listing(response):
    return response.status_code == 200 and "Index of" in response.text

def detect_insecure_client_access_policy(response):
    return "access-control-allow-origin" not in response.headers

def detect_missing_security_headers(response):
    missing_headers = []
    required_headers = [
        "Referrer-Policy",
        "Content-Security-Policy",
        "X-Content-Type-Options"
    ]
    for header in required_headers:
        if header not in response.headers:
            missing_headers.append(header)
    return missing_headers

def detect_unsafe_http_header_csp(response):
    csp_header = response.headers.get("Content-Security-Policy")
    return csp_header and "unsafe-inline" in csp_header

def detect_secure_cookie(response):
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.secure:
            return False
    return True

def detect_httponly_cookie(response):
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.has_nonstandard_attr("HttpOnly"):
            return False
    return True

def detect_security_txt(url):
    security_txt_url = f"{url}/.well-known/security.txt"
    try:
        response = requests.get(security_txt_url, timeout=5)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        return None

def xss_testing(url):
    vulnerable = False
    for payload in tags:
        try:
            test_url = f"{url}?test={payload}"
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                vulnerable = True
                break
        except requests.RequestException as e:
            print(f"Request failed during XSS testing with payload {payload}: {e}")
    
    return vulnerable
              

def sql_injection_testing(url):
    vulnerable = False
    for payload in sqltags:
        try:
            test_url = f"{url}{payload}"
            response = requests.get(test_url, timeout=5)
            if response.elapsed.total_seconds() > 20:
                vulnerable = True
                break
        except requests.exceptions.RequestException as e:
            print(f"Request failed with payload {payload}: {e}")
    return vulnerable

def scan_website(url):
    url = normalize_url(url)
    vulnerabilities = []
    
    try:
        response = requests.get(url, timeout=5)

        server_software = detect_server_software(response)
        if server_software:
            vulnerabilities.append(f"Server software: {server_software}")

        if detect_directory_listing(response):
            vulnerabilities.append("Directory listing is enabled")

        if detect_insecure_client_access_policy(response):
            vulnerabilities.append("Insecure client access policy")

        missing_headers = detect_missing_security_headers(response)
        if missing_headers:
            vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")

        if detect_unsafe_http_header_csp(response):
            vulnerabilities.append("Unsafe HTTP header Content Security Policy")

        if not detect_secure_cookie(response):
            vulnerabilities.append("Secure flag of cookie is not set")

        if not detect_httponly_cookie(response):
            vulnerabilities.append("HttpOnly flag of cookie is not set")

        security_txt = detect_security_txt(url)
        if security_txt:
            vulnerabilities.append(f"Security.txt: {security_txt}")

        # Use ThreadPoolExecutor to parallelize tests
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(xss_testing, url): "XSS",
                executor.submit(sql_injection_testing, url): "SQL Injection"
            }
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(f"{futures[future]} vulnerability found")
                except Exception as e:
                    vulnerabilities.append(f"Error in {futures[future]} test: {e}")

    except requests.RequestException as e:
        vulnerabilities.append(f"An error occurred while scanning: {e}")

    return vulnerabilities

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        if not url:
            return render_template("index.html", error="URL is required")

        vulnerabilities = scan_website(url)
        return render_template("index.html", vulnerabilities=vulnerabilities, url=url)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5010, debug=True)
