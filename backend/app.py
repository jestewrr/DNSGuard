from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from functools import wraps
from database import init_db, log_request, get_recent_logs, verify_user, get_user_by_id
from analyzer import analyze_url, extract_domain

app = Flask(__name__)
app.secret_key = 'dnsguard_super_secret_key_change_in_prod'

# Initialize database on startup
init_db()

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    user_id = session.get('user_id')
    role = session.get('role')
    
    # RBAC logic: Viewer/User only sees their own logs
    if role == 'Viewer/User':
        logs = get_recent_logs(user_id=user_id)
    else:
        logs = get_recent_logs()
    
    # Calculate simple stats
    total_requests = len(logs)
    safe_requests = sum(1 for log in logs if log['status'] == 'Safe')
    suspicious_requests = sum(1 for log in logs if log['status'] == 'Suspicious')
    malicious_requests = sum(1 for log in logs if log['status'] == 'Malicious')
    
    stats = {
        'total': total_requests,
        'safe': safe_requests,
        'suspicious': suspicious_requests,
        'malicious': malicious_requests
    }
    
    return render_template('dashboard.html', logs=logs, stats=stats, role=role, username=session.get('username'))

@app.route('/api/login', methods=['POST'])
def api_login():
    """Endpoint for the browser extension to authenticate."""
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing credentials'}), 400
        
    user = verify_user(data['username'], data['password'])
    if user:
        return jsonify({
            'success': True,
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role']
        })
    else:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/check_url', methods=['POST'])
def check_url():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
        
    url = data['url']
    user_id = data.get('user_id') # Extension should pass this if logged in
    domain = extract_domain(url)
    
    # Get client IP
    ip_address = request.remote_addr
    
    # Analyze the URL
    status, breakdown = analyze_url(url)
    
    # Log the request
    log_request(url, domain, status, ip_address, user_id=user_id, breakdown=breakdown)
    
    return jsonify({
        'url': url,
        'domain': domain,
        'status': status
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
