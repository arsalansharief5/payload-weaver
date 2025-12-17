from flask import Flask, render_template, request, redirect, url_for, flash, send_file,session,send_from_directory,abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import time
import requests
import crawler
import attack
import report_generator
from connection import connect_to_zap
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from queue import Queue
import threading
from flask_migrate import Migrate

# Initialize Migrate

# Initialize Flask app
app = Flask(__name__)

# Set up the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # For session management

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if user is not authenticated
migrate = Migrate(app, db)

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Create a global log queue
log_queue = Queue()



def log_message(message):
    """Add a log message to the queue."""
    log_queue.put(f"{datetime.now().strftime('%H:%M:%S')} - {message}")

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Enum('user', 'tester', 'admin', name='user_roles'), default='user', nullable=False)
    scanned_urls = db.relationship('ScannedURL', backref='owner', lazy=True)


from sqlalchemy import Enum

class ScannedURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    scan_duration = db.Column(db.Float, nullable=False)
    high_count = db.Column(db.Integer, default=0)  # High vulnerabilities count
    medium_count = db.Column(db.Integer, default=0)  # Medium vulnerabilities count
    low_count = db.Column(db.Integer, default=0)  # Low vulnerabilities count
    report_path = db.Column(db.String(300), nullable=True)  # Path to the generated report
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tester_assigned = db.Column(Enum('yes', 'no', name='tester_assigned'), default='no', nullable=False)


class Tester(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scanned_url_id = db.Column(db.Integer, db.ForeignKey('scanned_url.id'), nullable=False)
    status = db.Column(Enum('under review', 'in progress', 'completed', name='status_enum'), default='under review', nullable=False)

    # Relationships for easier access
    tester = db.relationship('User', foreign_keys=[tester_id])  # Links to the tester's user record
    scanned_url = db.relationship('ScannedURL', foreign_keys=[scanned_url_id])  # Links to the scanned URL

with app.app_context():
    db.create_all()

# Load the current user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/home')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']  # Get the role from the form

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user instance
        user = User(name=name, email=email, password=hashed_password, role=role)
        
        # Add the user to the database
        db.session.add(user)
        db.session.commit()
        
        # Flash a success message
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.pop('logged_in', None)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        # Get all users with the role 'user'
        users = User.query.filter_by(role='user').all()
        return render_template('admin.html', users=users, current_user=current_user)
    
    # elif current_user.role == 'manager':
    #     # Get all users with the role 'user'
    #     users = User.query.filter_by(role='user').all()
    #     return render_template('manager.html', users=users, current_user=current_user,scanned_urls=current_user.scanned_urls)
    elif current_user.role == 'tester':
        assignments = Tester.query.filter_by(tester_id=current_user.id).all()
        return render_template('tester_dashboard.html', assignments=assignments)
    else:
        # User dashboard logic
        scanned_urls = [
            {
                "target_url": url.target_url,
                "attack_type": url.attack_type,
                "scan_duration": url.scan_duration,
                "high_count": url.high_count,
                "medium_count": url.medium_count,
                "low_count": url.low_count
            }
            for url in current_user.scanned_urls
        ]
        return render_template('dashboard.html', scanned_urls=scanned_urls, current_user=current_user)
    
@app.route('/update_status/<int:assignment_id>', methods=['POST'])
@login_required
def update_status(assignment_id):
    if current_user.role != 'tester':
        abort(403)

    assignment = Tester.query.get_or_404(assignment_id)
    if assignment.tester_id != current_user.id:
        abort(403)  # Prevent testers from modifying tasks they are not assigned to

    new_status = request.form.get('status')
    assignment.status = new_status
    db.session.commit()

    flash(f"Status updated to {new_status} for task: {assignment.scanned_url.target_url}", "success")
    return redirect(url_for('dashboard'))

    
@app.route('/assign_tester/<int:scan_id>', methods=['POST'])
@login_required
def assign_tester(scan_id):
    if current_user.role != 'admin':
        abort(403)

    scan = ScannedURL.query.get_or_404(scan_id)
    if scan.tester_assigned == 'yes':  # Prevent re-assigning if already assigned
        flash('Tester has already been assigned to this vulnerability.', 'warning')
        return redirect(url_for('user_vulnerabilities', user_id=scan.user_id))

    tester_id = request.form.get('tester_id')
    tester = User.query.get(tester_id)

    if not tester or tester.role != 'tester':
        flash('Invalid tester selected.', 'danger')
        return redirect(url_for('user_vulnerabilities', user_id=scan.user_id))

    # Create a new Tester object and add it to the Tester table
    tester_assignment = Tester(tester_id=tester.id, scanned_url_id=scan.id)
    db.session.add(tester_assignment)

    # Update tester_assigned to 'yes'
    scan.tester_assigned = 'yes'
    db.session.commit()

    flash(f'Tester {tester.name} assigned to {scan.target_url}.', 'success')
    return redirect(url_for('user_vulnerabilities', user_id=scan.user_id))




@app.route('/user/<int:user_id>')
@login_required
def user_vulnerabilities(user_id):
    if current_user.role != 'admin':
        abort(403)  # Forbidden if the user is not an admin

    user = User.query.get_or_404(user_id)
    vulnerabilities = ScannedURL.query.filter_by(user_id=user.id).all()
    testers = User.query.filter_by(role='tester').all()
    
    # Attach the tester assignment details to each vulnerability
    vulnerabilities_with_tester = []
    for vulnerability in vulnerabilities:
        # Check if the vulnerability has a tester assigned
        assigned_tester = Tester.query.filter_by(scanned_url_id=vulnerability.id).first()
        if assigned_tester:
            vulnerability.tester_assigned = 'yes'
            vulnerability.tester_status = assigned_tester.status  # Add status
            vulnerability.tester_name = assigned_tester.tester.name  # Add tester's name
        else:
            vulnerability.tester_assigned = 'no'
            vulnerability.tester_status = None
            vulnerability.tester_name = None
        vulnerabilities_with_tester.append(vulnerability)

    return render_template('user_vulnerabilities.html', 
                           user=user, 
                           vulnerabilities=vulnerabilities_with_tester, 
                           testers=testers)



@app.route('/payloads')
@login_required
def payload_generate():
    print("HIT REQUEST")
    return render_template('aipage.html',
                           current_user=current_user)

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    """Handle the user's input and start the scan."""
    target_url = request.form['target_url']
    attack_mode = request.form['attack_mode']
    scan_type = request.form['scan_type']
    
    # Connect to ZAP
    zap_url = "https://localhost:8080" 
    api_key = "d4b8srkheoju3qe1uo8v6pm2k4" 

    zap = connect_to_zap(zap_url)
    if not zap:
        log_message("Failed to connect to ZAP. Please try again.")
        return "Failed to connect to ZAP. Please try again.", 500
    
    # Create a new session in ZAP
    log_message("Creating a new ZAP session...")
    create_zap_session(zap_url)

    # Start time for the scan
    log_message("Starting the scan...")
    start_time = time.time()

    # Crawling
    log_message("Crawling the target website...")
    crawl_data = crawler.crawl_website(zap, target_url)
    log_message("Crawling completed.")

    # Initialize vulnerabilities and attack_type
    vulnerabilities = []
    attack_type = ""
    
    # Perform attack based on user input
    log_message(f"Performing {attack_mode} attack...")
    if attack_mode == "1":
        vulnerabilities = attack.attack_website(zap, target_url, attack_type="xss",scan_type = scan_type)
        attack_type = "XSS"
    elif attack_mode == "2":
        vulnerabilities = attack.attack_website(zap, target_url, attack_type="sql_injection",scan_type = scan_type)
        attack_type = "SQL Injection"
    elif attack_mode == "3":
        vulnerabilities = attack.attack_website(zap, target_url, attack_type="command_injection",scan_type = scan_type)
        attack_type = "Command Injection"
    elif attack_mode == "4":
        vulnerabilities = attack.attack_website(zap, target_url, attack_type="all",scan_type = scan_type)
        attack_type = "All Attacks"
    log_message("Attacks completed.")

    # Calculate scan duration
    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)
    log_message(f"Scan completed in {scan_duration} seconds.")

    # Count vulnerabilities
    high_count = len([v for v in vulnerabilities if v['risk'] == "High"])
    medium_count = len([v for v in vulnerabilities if v['risk'] == "Medium"])
    low_count = len([v for v in vulnerabilities if v['risk'] == "Low"])

    # Generate report
    log_message("Generating the report...")
    start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = report_generator.generate_report(
        crawl_data=crawl_data,
        target_url=target_url,
        perform_attack="yes",
        vulnerabilities=vulnerabilities,
        scan_duration=scan_duration,
        start_time=start_time_str,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        attack_type=attack_type
    )
    # Save the scan result to the database
    scan = ScannedURL(
        target_url=target_url,
        attack_type=attack_type,
        scan_duration=scan_duration,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        report_path=report_path,
        user_id=current_user.id
)
    db.session.add(scan)
    db.session.commit()
    
    log_message("Report generated successfully.")

    return render_template('results.html', target_url=target_url, attack_type=attack_type, 
                       high_count=high_count, medium_count=medium_count, low_count=low_count,
                       scan_duration=scan_duration, report_path=report_path,
                       vulnerabilities=vulnerabilities)


@app.route('/download_report/<path:report_path>')
@login_required
def download_report(report_path):
    """Allow users to download the generated report."""
    return send_file(report_path, as_attachment=True)

# @app.route('/download_report2/<int:scan_id>')
# def download_report2(scan_id):
#     scanned_url = ScannedURL.query.get(scan_id)

def create_zap_session(zap_url):
    """Creates a new session in ZAP"""
    params = {
        'name': 'new_session',
        'overwrite': 'true'
    }
    try:
        response = requests.get(f'{zap_url}/JSON/core/action/newSession/', params=params, verify=False, timeout=30)
        if response.status_code == 200:
            log_message("New session created successfully.")
        else:
            log_message(f"Failed to create session. Response: {response.json()}")
    except requests.exceptions.RequestException as e:
        log_message(f"Error creating session: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
