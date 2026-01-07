from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os 
import uuid 

# --- Section 1: Imports & Initialization ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_strong_secret_key_999' 
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx'}
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Corrected helper function to check if a file extension is allowed
def allowed_file(filename):
    if '.' not in filename:
        return False
    # Get the file extension and convert to lowercase for comparison
    extension = filename.rsplit('.', 1)[-1].lower()
    return extension in app.config['ALLOWED_EXTENSIONS']

# --- Section 2: Database Models (Tables) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='job_seeker')
    resume_filename = db.Column(db.String(255)) 
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    contact_phone = db.Column(db.String(20))
    company_info = db.Column(db.Text)
    applications = db.relationship('Application', backref='applicant', lazy='dynamic')
    jobs_posted = db.relationship('Job', backref='employer', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def is_employer(self):
        return self.role == 'employer'
    def is_job_seeker(self):
        return self.role == 'job_seeker'
    
class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(50), nullable=False)
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    applications = db.relationship('Application', backref='job_applied_for', lazy='dynamic')

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_text = db.Column(db.Text, nullable=False)
    date_applied = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending') # NEW: Status field

# --- Section 3: Routes & Views (Web Pages) ---

@app.route('/')
def home():
    jobs_query = Job.query
    search_query = request.args.get('search_query', '')
    location_query = request.args.get('location', '')
    if search_query:
        jobs_query = jobs_query.filter((Job.title.like(f'%{search_query}%')) | (Job.description.like(f'%{search_query}%')))
    if location_query:
        jobs_query = jobs_query.filter(Job.location.like(f'%{location_query}%'))
    jobs = jobs_query.all()
    return render_template('home.html', jobs=jobs, search_query=search_query, location_query=location_query)

@app.route('/add_job', methods=['GET', 'POST'])
@login_required 
def add_job():
    if not current_user.is_employer():
        flash("You must be an employer to post a job.", "danger")
        return redirect(url_for('home'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        new_job = Job(title=title, description=description, location=location, employer_id=current_user.id)
        db.session.add(new_job)
        db.session.commit()
        flash('Job posted successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_job.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash('Logged in successfully.', 'info')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or Email already exists.', 'warning')
            return redirect(url_for('register'))
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply_to_job(job_id):
    if not current_user.is_job_seeker():
        flash("Employers cannot apply for jobs.", "danger")
        return redirect(url_for('home'))
    job = Job.query.get_or_404(job_id)
    if request.method == 'POST':
        application_text = request.form['application_text']
        existing_application = Application.query.filter_by(user_id=current_user.id, job_id=job.id).first()
        if existing_application:
            flash('You have already applied for this job!', 'warning')
            return redirect(url_for('home'))
        new_application = Application(job_id=job.id, user_id=current_user.id, application_text=application_text)
        db.session.add(new_application)
        db.session.commit()
        flash('Successfully applied for the job!', 'success')
        return redirect(url_for('home'))
    return render_template('apply_form.html', job=job)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_job_seeker():
        user_applications = Application.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard_jobseeker.html', applications=user_applications, user=current_user)
    elif current_user.is_employer():
        jobs_posted = Job.query.filter_by(employer_id=current_user.id).all()
        return render_template('dashboard_employer.html', jobs=jobs_posted, user=current_user)
    else:
        abort(403)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'update_info' in request.form:
            current_user.first_name = request.form['first_name']
            current_user.last_name = request.form['last_name']
            current_user.contact_phone = request.form['contact_phone']
            if current_user.is_employer():
                current_user.company_info = request.form['company_info']
            db.session.commit()
            flash('Profile information updated successfully!', 'success')
            return redirect(url_for('profile'))
        elif 'update_resume' in request.form:
            if 'resume' not in request.files:
                flash('No file part', 'danger')
                return redirect(request.url)
            file = request.files['resume']
            if file.filename == '':
                flash('No selected file', 'danger')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                extension = file.filename.rsplit('.', 1)[-1].lower()
                unique_filename = str(uuid.uuid4()) + '.' + extension
                filename = secure_filename(unique_filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                current_user.resume_filename = filename
                db.session.commit()
                flash('Resume successfully uploaded!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Allowed file types are PDF, DOC, DOCX.', 'danger')
    return render_template('profile.html', user=current_user)

@app.route('/update_application_status/<int:application_id>', methods=['POST'])
@login_required
def update_application_status(application_id):
    application = Application.query.get_or_404(application_id)
    new_status = request.form['status']
    if application.job_applied_for.employer_id != current_user.id:
        abort(403)
    application.status = new_status
    db.session.commit()
    flash(f'Application status updated to {new_status}.', 'success')
    return redirect(url_for('view_applicants', job_id=application.job_id))

@app.route('/view_applicants/<int:job_id>')
@login_required
def view_applicants(job_id):
    job = Job.query.get_or_404(job_id)
    if job.employer_id != current_user.id:
        abort(403)
    applications = Application.query.filter_by(job_id=job.id).all()
    return render_template('view_applicants.html', job=job, applications=applications)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# --- Section 4: Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        # CRITICAL: If you get a 'no such column' error, delete the 'site.db' file!
        db.create_all() 
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

    app.run(debug=True, port=5000)
