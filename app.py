import os
import time
from datetime import datetime
from queue import Empty, Queue
from urllib.parse import urlparse

import attack
import crawler
import report_generator
import urllib3
import utils
from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    stream_with_context,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from connection import connect_to_zap
from urllib3.exceptions import InsecureRequestWarning
from flask_migrate import Migrate

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False

# Initialize Migrate

# Initialize Flask app
load_dotenv()
app = Flask(__name__)

# Set up the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')  # For session management

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if user is not authenticated
migrate = Migrate(app, db)

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Create a global log queue
log_queue = Queue()
REPORTS_DIR = os.path.join(app.root_path, "static", "reports")



def log_message(message):
    """Add a log message to the queue."""
    log_queue.put(f"{datetime.now().strftime('%H:%M:%S')} - {message}")


def clear_log_queue():
    while not log_queue.empty():
        try:
            log_queue.get_nowait()
        except Empty:
            break


def normalize_target_url(raw_url):
    raw_url = raw_url.strip()
    if not raw_url:
        return ""
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"

    parsed = urlparse(raw_url)
    if not parsed.netloc:
        return ""
    return raw_url

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
    high_count = db.Column(db.Integer, default=0)  
    medium_count = db.Column(db.Integer, default=0)  
    low_count = db.Column(db.Integer, default=0)  
    report_path = db.Column(db.String(300), nullable=True)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tester_assigned = db.Column(Enum('yes', 'no', name='tester_assigned'), default='no', nullable=False)


class Tester(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scanned_url_id = db.Column(db.Integer, db.ForeignKey('scanned_url.id'), nullable=False)
    status = db.Column(Enum('under review', 'in progress', 'completed', name='status_enum'), default='under review', nullable=False)

    tester = db.relationship('User', foreign_keys=[tester_id])  
    scanned_url = db.relationship('ScannedURL', foreign_keys=[scanned_url_id])  

with app.app_context():
    db.create_all()

# Load the current user
#whenever you want to get the user from the db run this function, we are telling this to flask
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('index'))


@app.route('/welcome')
def welcome():
    return render_template('home.html')


@app.route('/health')
def health():
    return {"status": "ok"}, 200


@app.route('/home')
def index():
    return render_template('index_modern.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = 'user' # Get the role from the form

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
    
    return render_template('register_modern.html')


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
            # this also stores userid in cookies
            # triggers the load_user() and retrieves the user
            # this informs flask that the user session has started and on every subsequnt requests load the user from load_user() because of the  decorator(line 85)
            # also loads the user retrieved into current_user
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    
    return render_template('login_modern.html')

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
        return render_template('admin_modern.html', users=users, current_user=current_user)
    
    elif current_user.role == 'tester':
        assignments = Tester.query.filter_by(tester_id=current_user.id).all()
        return render_template('tester_dashboard_modern.html', assignments=assignments)
    else:
        # User dashboard logic
        scanned_urls = [
            {
                "id": url.id,
                "target_url": url.target_url,
                "attack_type": url.attack_type,
                "scan_duration": url.scan_duration,
                "high_count": url.high_count,
                "medium_count": url.medium_count,
                "low_count": url.low_count,
                "report_filename": os.path.basename(url.report_path) if url.report_path else None,
            }
            for url in current_user.scanned_urls
        ]
        return render_template('dashboard_modern.html', scanned_urls=scanned_urls, current_user=current_user)
    
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

    #well get the target url for which we are assigning the tester like well get the entire scanned url object
    scan = ScannedURL.query.get_or_404(scan_id)

    #this case wont ever occur but this is just a safety check, we are providing the dropn down only if the tester is not already assigned
    if scan.tester_assigned == 'yes':  # Prevent re-assigning if already assigned
        flash('Tester has already been assigned to this vulnerability.', 'warning')
        return redirect(url_for('user_vulnerabilities', user_id=scan.user_id))

    #get the tester id from the form(value of the drop down) and then get the tester object
    tester_id = request.form.get('tester_id')
    tester = User.query.get(tester_id)

    if not tester or tester.role != 'tester':
        flash('Invalid tester selected.', 'danger')
        return redirect(url_for('user_vulnerabilities', user_id=scan.user_id))

    # Create a new Tester object and add it to the Tester table
    tester_assignment = Tester(tester_id=tester.id, scanned_url_id=scan.id)
    db.session.add(tester_assignment)

    # Update tester_assigned to 'yes' in the scanned_url table
    scan.tester_assigned = 'yes'
    db.session.commit()

    flash(f'Tester {tester.name} assigned to {scan.target_url}.', 'success')
    return redirect(url_for('user_vulnerabilities', user_id=scan.user_id))




@app.route('/user/<int:user_id>')
@login_required
def user_vulnerabilities(user_id):
    if current_user.role != 'admin':
        abort(403)  # Forbidden if the user is not an admin

    #getting the user object of the particular user id whom we decided to view details of
    user = User.query.get_or_404(user_id)

    #getting the list of all the vulnerabilites the user has scanned so far
    vulnerabilities = ScannedURL.query.filter_by(user_id=user.id).all()

    #getting all the users who are testers in the database
    testers = User.query.filter_by(role='tester').all()
    
    # Attach the tester assignment details to each vulnerability
    vulnerabilities_with_tester = []
    for vulnerability in vulnerabilities:
        # Check if the vulnerability has a tester assigned, it does so by checking if the vulnerability is added to the tester table or not
        #An entry is made to the tester table only after a tester is assingned to the scanned_url_id
        #it will return the test object if the tester is already assigend else it will return none
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

    return render_template('user_vulnerabilities_modern.html', 
                           user=user, 
                           vulnerabilities=vulnerabilities_with_tester, 
                           testers=testers)
    
@app.route('/registeradmin', methods=['GET', 'POST'])
def register1():
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
        flash("Registration successful!", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('registeradmin_modern.html')
@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    clear_log_queue()
    target_urls = []
    for url in request.form['target_url'].split(','):
        normalized_url = normalize_target_url(url)
        if normalized_url:
            target_urls.append(normalized_url)
    scan_type = request.form.get('scan_type', 'regular')
    ai_assisted = scan_type == 'ai_assisted'

    if not target_urls:
        flash("Enter at least one valid website URL to scan.", "danger")
        return redirect(url_for('index'))

    zap = connect_to_zap()
    if not zap:
        log_message("ZAP connection failed. Start OWASP ZAP in daemon mode and try again.")
        flash("Could not connect to OWASP ZAP. Start ZAP locally, then retry the scan.", "danger")
        return redirect(url_for('index'))

    log_message(f"Connected to ZAP at {getattr(zap, 'proxy_url', 'unknown endpoint')}.")
    log_message("Creating a fresh ZAP session...")
    create_zap_session(zap)

    combined_results = {
        'scan_start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'total_scan_duration': 0,
        'urls_scanned': [],
        'total_vulnerabilities': {
            'High': 0,
            'Medium': 0,
            'Low': 0
        },
        'detailed_results': []
    }
    scan_records = []
    last_result = {
        "target_url": target_urls[0],
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "vulnerabilities": [],
        "scan_duration": 0,
        "attack_type": "AI-Assisted ZAP Scan" if ai_assisted else f"{scan_type.title()} ZAP Scan",
        "site_category": None,
        "ai_summary": None,
    }

    for target_url in target_urls:
        start_time = time.time()
        log_message(f"Starting scan for {target_url}...")
        log_message("Running ZAP spider...")
        crawl_data = crawler.crawl_website(zap, target_url)
        log_message(f"Spider finished with {crawl_data['num_crawls']} discovered URLs.")
        site_category = None
        ai_summary = None

        zap_scan_type = scan_type
        if ai_assisted:
            log_message("Collecting site content for AI classification...")
            site_category, _ = utils.classify_website(target_url)
            if site_category:
                log_message(f"AI classified the site as {site_category}.")
            else:
                log_message("AI classification was unavailable. Check OPENAI_API_KEY and network access, then retry if needed.")
            zap_scan_type = "deep"

        log_message(f"Running {zap_scan_type} ZAP analysis...")
        vulnerabilities = attack.attack_website(zap, target_url, zap_scan_type, "all")
        attack_type = "AI-Assisted ZAP Scan" if ai_assisted else f"{scan_type.title()} ZAP Scan"
        log_message(f"Analysis completed with {len(vulnerabilities)} findings.")

        if ai_assisted:
            log_message("Generating AI remediation summary...")
            ai_summary = utils.generate_ai_scan_summary(target_url, site_category, crawl_data, vulnerabilities)
            if ai_summary:
                log_message("AI remediation summary added to the report.")
            else:
                log_message("AI summary unavailable. The scan results will still include the raw ZAP findings.")

        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)
        log_message(f"Scan completed in {scan_duration} seconds.")

        vuln_counts = {
            'High': len([v for v in vulnerabilities if v['risk'] == "High"]),
            'Medium': len([v for v in vulnerabilities if v['risk'] == "Medium"]),
            'Low': len([v for v in vulnerabilities if v['risk'] == "Low"])
        }

        combined_results['total_scan_duration'] += scan_duration
        combined_results['urls_scanned'].append(target_url)
        for severity in ['High', 'Medium', 'Low']:
            combined_results['total_vulnerabilities'][severity] += vuln_counts[severity]

        combined_results['detailed_results'].append({
            'url': target_url,
            'scan_duration': scan_duration,
            'crawl_data': crawl_data,
            'attack_performed': True,
            'attack_type': attack_type,
            'vulnerabilities': vulnerabilities,
            'vulnerability_counts': vuln_counts,
            'site_category': site_category,
            'ai_summary': ai_summary,
        })

        scan = ScannedURL(
            target_url=target_url,
            attack_type=attack_type,
            scan_duration=scan_duration,
            high_count=vuln_counts['High'],
            medium_count=vuln_counts['Medium'],
            low_count=vuln_counts['Low'],
            report_path="",
            user_id=current_user.id
        )
        db.session.add(scan)
        scan_records.append(scan)
        last_result = {
            "target_url": target_url,
            "high_count": vuln_counts['High'],
            "medium_count": vuln_counts['Medium'],
            "low_count": vuln_counts['Low'],
            "vulnerabilities": vulnerabilities,
            "scan_duration": scan_duration,
            "attack_type": attack_type,
            "site_category": site_category,
            "ai_summary": ai_summary,
        }

    log_message("Generating the combined report...")
    combined_results['scan_end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    combined_report_path = report_generator.generate_combined_report(combined_results)
    report_filename = os.path.basename(combined_report_path)

    for scan_record in scan_records:
        scan_record.report_path = combined_report_path

    db.session.commit()
    log_message("Report generated successfully.")

    return render_template(
        'results_modern.html',
        target_url=last_result["target_url"],
        combined_results=combined_results,
        report_filename=report_filename,
        high_count=last_result["high_count"],
        medium_count=last_result["medium_count"],
        low_count=last_result["low_count"],
        vulnerabilities=last_result["vulnerabilities"],
        attack_type=last_result["attack_type"],
        scan_duration=last_result["scan_duration"],
        site_category=last_result["site_category"],
        ai_summary=last_result["ai_summary"],
        scan_mode=scan_type,
    )


@app.route('/download_report/<path:report_name>')
@login_required
def download_report(report_name):
    """Allow users to download the generated report."""
    safe_name = os.path.basename(report_name)
    report_path = os.path.join(REPORTS_DIR, safe_name)
    if not os.path.exists(report_path):
        abort(404)
    return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)

@app.route('/logs')
def stream_logs():
    @stream_with_context
    def event_stream():
        while True:
            try:
                message = log_queue.get(timeout=15)
                yield f"data: {message}\n\n"
            except Empty:
                yield "data: waiting for scan updates...\n\n"

    return Response(event_stream(), mimetype='text/event-stream')


def create_zap_session(zap):
    try:
        zap.core.new_session(name='payloadweaver', overwrite=True)
        log_message("New session created successfully.")
    except Exception as e:
        log_message(f"Error creating session: {e}")

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )
