#!/usr/bin/env python3
"""
Sample Vulnerable Python File
===============================
This file contains intentional security vulnerabilities
for testing the AI-Powered OWASP Scanner.

WARNING: Do NOT use any of this code in production.
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ============================================================
# A03:2021 - Injection (SQL Injection)
# ============================================================
def get_user(user_id):
    """Vulnerable to SQL injection."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string formatting in SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()


# ============================================================
# A03:2021 - Injection (Command Injection)
# ============================================================
@app.route('/ping')
def ping():
    """Vulnerable to command injection."""
    host = request.args.get('host', '')
    # VULNERABLE: User input directly in shell command
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result.decode()


# ============================================================
# A03:2021 - Injection (Server-Side Template Injection)
# ============================================================
@app.route('/greet')
def greet():
    """Vulnerable to SSTI."""
    name = request.args.get('name', 'World')
    # VULNERABLE: User input in template string
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


# ============================================================
# A02:2021 - Cryptographic Failures
# ============================================================
def store_password(password):
    """Storing password in plain text."""
    # VULNERABLE: No hashing, no encryption
    with open('passwords.txt', 'a') as f:
        f.write(password + '\n')


# ============================================================
# A07:2021 - Identification and Authentication Failures
# ============================================================
# VULNERABLE: Hardcoded credentials
DATABASE_PASSWORD = "admin123"
API_SECRET_KEY = "sk-1234567890abcdef"


# ============================================================
# A05:2021 - Security Misconfiguration
# ============================================================
@app.route('/debug')
def debug_endpoint():
    """Exposes sensitive environment information."""
    # VULNERABLE: Leaking environment variables
    return str(dict(os.environ))


# ============================================================
# A01:2021 - Broken Access Control (IDOR)
# ============================================================
@app.route('/user/<user_id>')
def user_profile(user_id):
    """No authorization check - any user can access any profile."""
    # VULNERABLE: No authentication or authorization
    user = get_user(user_id)
    return str(user)


# ============================================================
# A08:2021 - Software and Data Integrity Failures
# ============================================================
import pickle

@app.route('/load', methods=['POST'])
def load_data():
    """Vulnerable to insecure deserialization."""
    # VULNERABLE: Deserializing untrusted data
    data = pickle.loads(request.data)
    return str(data)


# ============================================================
# A10:2021 - Server-Side Request Forgery (SSRF)
# ============================================================
import requests as http_requests

@app.route('/fetch')
def fetch_url():
    """Vulnerable to SSRF."""
    url = request.args.get('url', '')
    # VULNERABLE: Fetching arbitrary URLs from user input
    response = http_requests.get(url)
    return response.text


if __name__ == '__main__':
    # VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=5000)
