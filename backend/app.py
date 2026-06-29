from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from functools import wraps
from database import (
    init_db, log_request, get_recent_logs, get_log_stats,
    verify_user, get_user_by_id, create_user, get_all_users, update_user, delete_user,
    update_last_login, reclassify_log,
    get_blacklist, get_whitelist, add_to_blacklist, remove_from_blacklist,
    add_to_whitelist, remove_from_whitelist,
    create_reset_token, verify_reset_token, reset_password
)
from analyzer import analyze_url, extract_domain
import json

app = Flask(__name__)
app.secret_key = 'dnsguard_super_secret_key_change_in_prod'

# Initialize database on startup
init_db()

# ──────────────────────────────────────────────
# Security Headers Middleware (Fixes scanned vulnerabilities)
# ──────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    # Prevent Clickjacking (X-Frame-Options)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Prevent MIME Sniffing (X-Content-Type-Options)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enforce HTTPS (Strict-Transport-Security)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Content Security Policy (Allows our CDNs for Tailwind, Bootstrap, Google Fonts, and Chart.js)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    
    # Cross-Site Scripting Protection (X-XSS-Protection) - Legacy protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy (Referrer-Policy)
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy (Permissions-Policy) - Restrict device access
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Hide Web Server Info (Server Version Disclosure)
    response.headers['Server'] = 'SecureDNS-Shield'
    
    return response

# ──────────────────────────────────────────────
# Decorators
# ──────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'Administrator':
            flash('Access denied. Administrator privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    """Allows both Security Analyst and Administrator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') not in ('Security Analyst', 'Administrator'):
            flash('Access denied. Security Analyst privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ──────────────────────────────────────────────
# Auth Routes
# ──────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('login.html')

        user = verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user.get('full_name', user['username'])
            if remember:
                session.permanent = True
            update_last_login(user['id'])
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not all([full_name, username, email, password, confirm_password]):
            flash('All fields are required.', 'error')
            return render_template('register.html')
        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return render_template('register.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        if '@' not in email:
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html')

        success, result = create_user(full_name, username, email, password, role='Viewer/User')
        if success:
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(result, 'error')

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')
        success, token_or_msg = create_reset_token(email)
        if success:
            reset_link = url_for('reset_password_page', token=token_or_msg, _external=True)
            flash(f'Password reset link has been generated. In production, this would be emailed. For now, use this link: {reset_link}', 'info')
        else:
            # Don't reveal whether the email exists
            flash('If an account with that email exists, a reset link has been sent.', 'info')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_page(token):
    user_id = verify_reset_token(token)
    if not user_id:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('reset_password.html', token=token)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        if reset_password(token, password):
            flash('Password reset successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('An error occurred. Please try again.', 'error')

    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ──────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    user_id = session.get('user_id')
    role = session.get('role')

    # RBAC: Viewer sees only own logs
    if role == 'Viewer/User':
        logs = get_recent_logs(user_id=user_id)
        stats = get_log_stats(user_id=user_id)
    else:
        logs = get_recent_logs()
        stats = get_log_stats()

    return render_template('dashboard.html',
        logs=logs,
        stats=stats,
        role=role,
        username=session.get('username'),
        full_name=session.get('full_name', session.get('username'))
    )

# ──────────────────────────────────────────────
# Admin: User Management
# ──────────────────────────────────────────────

@app.route('/admin/users')
@admin_required
def admin_users():
    users = get_all_users()
    return render_template('admin_users.html',
        users=users,
        role=session.get('role'),
        username=session.get('username'),
        full_name=session.get('full_name')
    )

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_create_user():
    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'Viewer/User')

    if not all([full_name, username, email, password]):
        flash('All fields are required.', 'error')
        return redirect(url_for('admin_users'))

    success, result = create_user(full_name, username, email, password, role=role)
    if success:
        flash(f'User "{username}" created successfully.', 'success')
    else:
        flash(f'Error: {result}', 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    full_name = request.form.get('full_name')
    email = request.form.get('email')
    role = request.form.get('role')
    is_active = request.form.get('is_active') == 'true'

    update_user(user_id, full_name=full_name, email=email, role=role, is_active=is_active)
    flash('User updated successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    # Prevent admin from deleting themselves
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_users'))
    delete_user(user_id)
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

# ──────────────────────────────────────────────
# Admin: Settings (Blacklist / Whitelist)
# ──────────────────────────────────────────────

@app.route('/admin/settings')
@admin_required
def admin_settings():
    blacklist = get_blacklist()
    whitelist = get_whitelist()
    return render_template('admin_settings.html',
        blacklist=blacklist,
        whitelist=whitelist,
        role=session.get('role'),
        username=session.get('username'),
        full_name=session.get('full_name')
    )

@app.route('/admin/blacklist/add', methods=['POST'])
@admin_required
def admin_add_blacklist():
    domain = request.form.get('domain', '').strip().lower()
    if domain:
        add_to_blacklist(domain)
        flash(f'"{domain}" added to blacklist.', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin/blacklist/<int:domain_id>/remove', methods=['POST'])
@admin_required
def admin_remove_blacklist(domain_id):
    remove_from_blacklist(domain_id)
    flash('Domain removed from blacklist.', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin/whitelist/add', methods=['POST'])
@admin_required
def admin_add_whitelist():
    domain = request.form.get('domain', '').strip().lower()
    if domain:
        add_to_whitelist(domain)
        flash(f'"{domain}" added to whitelist.', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin/whitelist/<int:domain_id>/remove', methods=['POST'])
@admin_required
def admin_remove_whitelist(domain_id):
    remove_from_whitelist(domain_id)
    flash('Domain removed from whitelist.', 'success')
    return redirect(url_for('admin_settings'))

# ──────────────────────────────────────────────
# Analyst: Reclassify
# ──────────────────────────────────────────────

@app.route('/analyst/reclassify/<int:log_id>', methods=['POST'])
@analyst_required
def analyst_reclassify(log_id):
    new_status = request.form.get('status')
    if new_status not in ('Safe', 'Suspicious', 'Malicious'):
        flash('Invalid status.', 'error')
        return redirect(url_for('dashboard'))
    reclassify_log(log_id, new_status)
    flash(f'Log #{log_id} reclassified as {new_status}.', 'success')
    return redirect(url_for('dashboard'))

# ──────────────────────────────────────────────
# API Endpoints (for the browser extension)
# ──────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing credentials'}), 400
    user = verify_user(data['username'], data['password'])
    if user:
        update_last_login(user['id'])
        return jsonify({
            'success': True,
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role']
        })
    else:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    if not data:
        return jsonify({'error': 'Missing data'}), 400
    required = ['full_name', 'username', 'email', 'password']
    for field in required:
        if field not in data or not data[field].strip():
            return jsonify({'error': f'{field} is required'}), 400
    success, result = create_user(data['full_name'], data['username'], data['email'], data['password'])
    if success:
        return jsonify({'success': True, 'user_id': result})
    else:
        return jsonify({'success': False, 'error': result}), 400

@app.route('/api/check_url', methods=['POST'])
def check_url():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400

    url = data['url']
    user_id = data.get('user_id')
    domain = extract_domain(url)
    ip_address = request.remote_addr

    status, breakdown = analyze_url(url)
    log_request(url, domain, status, ip_address, user_id=user_id, breakdown=breakdown)

    return jsonify({
        'url': url,
        'domain': domain,
        'status': status,
        'breakdown': breakdown
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
