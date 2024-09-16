from flask import Flask, request, render_template
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from tags import tags
from sqltags import sqltags
from urllib.parse import urlparse

app = Flask(__name__)

def normalize_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = f"http://{url}"
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
        response = requests.get(security_txt_url)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        return None

def xss_testing(url):
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    
    xss_vulnerable = False

    for payload in tags:
        try:
            driver.execute_script(f"document.body.innerHTML = '{payload}'")
            xss_vulnerable = True
            break
        except Exception as e:
            print(f"Error during XSS testing with payload {payload}: {e}")

    driver.quit()
    return xss_vulnerable

def sql_injection_testing(url):
    vulnerable = False
    for payload in sqltags:
        try:
            test_url = f"{url}{sqltags}"
            response = requests.get(test_url)
            if response.elapsed.total_seconds() > 20:
                print(f"Potential SQL Injection vulnerability found with payload: {sqltags}")
                vulnerable = True
                break
        except requests.exceptions.RequestException as e:
            print(f"Request failed with payload {sqltags}q: {e}")
    return vulnerable

def scan_website(url):
    url = normalize_url(url)
    vulnerabilities = []
    try:
        response = requests.get(url)
        
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

        if xss_testing(url):
            vulnerabilities.append("XSS vulnerability found")

        if sql_injection_testing(url):
            vulnerabilities.append("SQL injection vulnerability found")

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
        return render_template("result.html", vulnerabilities=vulnerabilities, url=url)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
