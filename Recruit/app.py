from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, flash, url_for,g
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import os
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import google.generativeai as genai
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import text
from datetime import datetime, timedelta
import threading
import time,schedule , smtplib,imaplib,unicodedata,re ,email,json
import pandas as pd
from email.mime.text import MIMEText
from routes import register_blueprints
from models import db, Job, Application, InterviewSchedule, Feedback, AcceptedCandidate, User, JobOffer, Slot
import logging
from email_utils import (
    send_initial_rejection_email,
    send_reminder_email,
    send_schedule_email,
    send_rejection_email,
    send_email
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app)
register_blueprints(app)
bcrypt = Bcrypt(app)

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/JobApplications35'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_super_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'

# Email configuration (add to your config file)
EMAIL_CONFIG = {
    "email_address": "your_email@gmail.com",
    "email_password": "your_app_password"
}
SMTP_SERVER = "smtp.gmail.com"
IMAP_SERVER = "imap.gmail.com"
TIMEOUT_HOURS = 24  # Hours to wait for offer response

db.init_app(app)
with app.app_context():
    db.create_all()

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable is not set.")
genai.configure(api_key="AIzaSyAcAJFHI_jyahZa7bCC3s04yHm9ujbq2_I")

# ==================== INTEGRATED EMAIL OFFER SYSTEM ====================

def normalize_unicode(text):
    """Normalize unicode characters in text"""
    normalized = unicodedata.normalize('NFKD', text)
    replacements = {
        ''': "'", ''': "'", '"': '"', '"': '"',
        '…': '...', '–': '-', '—': '--', 'ʼ': "'"
    }
    for k, v in replacements.items():
        normalized = normalized.replace(k, v)
    return normalized

def clean_email_body(raw_body):
    """Clean email body by removing signatures and quoted text"""
    text = normalize_unicode(raw_body)
    separators = [
        r"On.wrote:", r"From:\s.", r"Sent:\s.", r"To:\s.", r"Subject:\s.*",
        r"-----Original Message-----", r"^\s*>", r"^\s*--\s*$", r"Best regards",
        r"Kind regards", r"Regards", r"Cheers", r"Sincerely"
    ]
    lines = text.split('\n')
    clean_lines = []
    for line in lines:
        line = line.strip()
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in separators):
            break
        if line and not line.startswith('>'):
            clean_lines.append(line)
    clean_text = ' '.join(clean_lines)
    return re.sub(r'\s+', ' ', clean_text).strip()

def classify_with_gemini(text):
    """Classify email response as accepted or rejected using Gemini AI"""
    model = genai.GenerativeModel('gemini-2.5-flash')
    prompt = f"""Classify this email response to a job offer as 'accepted' or 'rejected'. 
    Look for clear acceptance or rejection language. Be strict in classification.
    Text: "{text}" 
    Respond with only 'accepted' or 'rejected'."""
    try:
        response = model.generate_content(prompt)
        result = response.text.strip().lower()
        return "accepted" if "accept" in result and "reject" not in result else "rejected"
    except Exception as e:
        logging.error(f"Gemini classification error: {e}")
        return "rejected"

def send_job_offer_email(to_email, name, job_position, company_name="Our Company"):
    """Send job offer email to candidate"""
    msg = MIMEText(f"""Dear {name},

We are delighted to offer you the position of {job_position} at {company_name}.

We were impressed by your qualifications and believe you would be a valuable addition to our team.

Please reply to this email within 24 hours to confirm your acceptance of this offer.

If you have any questions, please don't hesitate to contact us.

Best regards,
HR Team
{company_name}""")
    
    msg["Subject"] = f"Job Offer - {job_position} Position"
    msg["From"] = EMAIL_CONFIG["email_address"]
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["email_address"], EMAIL_CONFIG["email_password"])
            server.send_message(msg)
        logging.info(f"Job offer email sent to {to_email}")
        return True
    except Exception as e:
        logging.error(f"Email send error: {e}")
        return False

def get_email_responses():
    """Check for email responses to job offers"""
    responses = {}
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, 993)
        mail.login(EMAIL_CONFIG["email_address"], EMAIL_CONFIG["email_password"])
        mail.select("inbox")
        
        # Search for replies to job offers
        status, data = mail.search(None, '(UNSEEN SUBJECT "Re: Job Offer")')
        
        for num in data[0].split():
            _, msg_data = mail.fetch(num, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            sender = email.utils.parseaddr(msg["From"])[1]

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and "attachment" not in str(part.get("Content-Disposition")):
                        body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                        break
            else:
                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore")

            clean_body = clean_email_body(body)
            responses[sender] = classify_with_gemini(clean_body)
            
            # Mark email as read
            mail.store(num, "+FLAGS", "\\Seen")
            
        mail.close()
        mail.logout()
    except Exception as e:
        logging.error(f"IMAP error: {e}")
    
    return responses

def process_job_offers():
    """Process job offers and handle responses"""
    try:
        # Get email responses
        email_responses = get_email_responses()
        
        # Check for pending offers that need to be sent
        pending_offers = JobOffer.query.filter_by(status='pending', offer_sent=False).all()
        
        for offer in pending_offers:
            application = Application.query.get(offer.application_id)
            if application:
                job = Job.query.get(application.job_id)
                if send_job_offer_email(application.applicant_email, application.applicant_name, job.title):
                    offer.offer_sent = True
                    offer.offer_sent_time = datetime.now()
                    db.session.commit()
                    logging.info(f"Offer sent to {application.applicant_name}")
                    break  # Send one offer at a time
        
        # Process email responses
        for email_addr, response in email_responses.items():
            application = Application.query.filter_by(applicant_email=email_addr).first()
            if application:
                offer = JobOffer.query.filter_by(application_id=application.id, status='pending').first()
                if offer:
                    if response == 'accepted':
                        offer.status = 'accepted'
                        application.status = 'Hired'
                        # Create accepted candidate record
                        accepted_candidate = AcceptedCandidate(
                            candidate_id=application.id,
                            applicant_name=application.applicant_name,
                            applicant_email=application.applicant_email
                        )
                        db.session.add(accepted_candidate)
                        logging.info(f"Offer accepted by {application.applicant_name}")
                    else:
                        offer.status = 'rejected'
                        application.status = 'Rejected'
                        logging.info(f"Offer rejected by {application.applicant_name}")
                    
                    db.session.commit()
        
        # Check for timed out offers
        timeout_threshold = datetime.now() - timedelta(hours=TIMEOUT_HOURS)
        timed_out_offers = JobOffer.query.filter(
            JobOffer.status == 'pending',
            JobOffer.offer_sent == True,
            JobOffer.offer_sent_time < timeout_threshold
        ).all()
        
        for offer in timed_out_offers:
            offer.status = 'expired'
            application = Application.query.get(offer.application_id)
            if application:
                application.status = 'Offer Expired'
            db.session.commit()
            logging.info(f"Offer expired for application {offer.application_id}")
            
    except Exception as e:
        logging.error(f"Error processing job offers: {e}")
        db.session.rollback()

# ==================== NEW ROUTES FOR OFFER MANAGEMENT ====================

@app.route('/offers', methods=['GET'])
def view_offers():
    companyName = session.get('company_name')
    if not companyName:
        return redirect(url_for('login'))
    companies = JobOffer.query
    offers = companies.filter_by(company_name="Devorks").all()
    print(offers)
    return render_template('offers.html', offers=offers)

@app.route('/offers/create', methods=['POST'])
def create_offer():
    """Create a new job offer"""
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401
    
    data = request.get_json()
    application_id = data.get('application_id')
    
    if not application_id:
        return jsonify({"message": "Application ID required"}), 400
    
    # Check if application exists and is eligible for offer
    application = Application.query.get(application_id)
    if not application:
        return jsonify({"message": "Application not found"}), 404
    
    if application.status not in ['Accepted']:
        return jsonify({"message": "Application not eligible for offer"}), 400
    
    # Check if offer already exists
    existing_offer = JobOffer.query.filter_by(application_id=application_id).first()
    if existing_offer:
        return jsonify({"message": "Offer already exists for this application"}), 400
    
    # Create new offer
    new_offer = JobOffer(
        application_id=application_id,
        status='pending',
        offer_sent=False
    )
    
    db.session.add(new_offer)
    db.session.commit()
    
    return jsonify({"message": "Offer created successfully", "offer_id": new_offer.id}), 201

@app.route('/offers/process', methods=['POST'])
def manual_process_offers():
    """Manually trigger offer processing"""
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401
    
    process_job_offers()
    return jsonify({"message": "Offers processed successfully"}), 200

@app.route('/offers/dashboard')
def offers_dashboard():
    """Dashboard for job offers"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get statistics
    total_offers = JobOffer.query.count()
    pending_offers = JobOffer.query.filter_by(status='pending').count()
    accepted_offers = JobOffer.query.filter_by(status='accepted').count()
    rejected_offers = JobOffer.query.filter_by(status='rejected').count()
    expired_offers = JobOffer.query.filter_by(status='expired').count()
    
    stats = {
        'total': total_offers,
        'pending': pending_offers,
        'accepted': accepted_offers,
        'rejected': rejected_offers,
        'expired': expired_offers
    }
    
    return render_template('offers_dashboard.html', stats=stats)
# ==================== Adding the slots ====================
@app.route('/slots/add', methods=['GET', 'POST'])
def add_slots():
    # Only allow certain roles (e.g., admin, HR) to add slots
    # if session.get('user_role') not in ['admin', 'hr']:
    #     flash('You do not have permission to add slots.', 'error')
    #     return redirect(url_for('dashboard')) # Or appropriate page
   
    if request.method == 'POST':
        data = request.get_json() 
        company_name = data.get('company_name')
        role = data.get('role')
        interview_time_str = data.get('interview_time')
        interviewer_name = data.get('interviewer_name')
        interviewer_email = data.get('interviewer_email')
        mode = data.get('mode')
        meeting_link = data.get('meeting_link')
        address = data.get('address')
        

        if not all([company_name, role, interview_time_str, interviewer_name, interviewer_email, mode]):
            print(company_name)
            return jsonify({"message": "Missing required fields"}), 400

        try:
            # Parse datetime string from HTML form (example: 2025-06-19T14:30)
            interview_time = datetime.fromisoformat(interview_time_str)
        except ValueError:
            return jsonify({"message": "Invalid date/time format"}), 400

        # Basic validation for mode-specific fields
        if mode == 'online' and not meeting_link:
            return jsonify({"message": "Meeting link is required for online interviews"}), 400
        if mode == 'offline' and not address:
            return jsonify({"message": "Address is required for in-person interviews"}), 400
        
        # Ensure meeting_link/address is None if not applicable, for cleaner data
        if mode != 'online': meeting_link = None
        if mode != 'offline': address = None

        new_slot = Slot(
            company_name=company_name,
            role=role,
            interview_time=interview_time,
            interviewer_name=interviewer_name,
            interviewer_email=interviewer_email,
            mode=mode,
            meeting_link=meeting_link,
            address=address,
            is_booked=False # Initially not booked
        )
        db.session.add(new_slot)
        db.session.commit()
        return jsonify({"message": "Slot added successfully", "slot_id": new_slot.id}), 201
    
    # GET request for adding slots
    return render_template('add_slot.html') # You'll create this HTML template


# --- New Route to View Available Slots ---

@app.before_request
def inject_now():
    """Injects the current datetime into the Flask global context for Jinja2."""
    g.now = datetime.now # This is correct for setting g.now


@app.route('/slots', methods=['GET'])
def view_slots():
    # Fetch all unbooked slots or filter by company/role if needed
    # You might want to filter by user's company if 'company_name' in Slot matches User's company
    current_user_id = session.get('user_id')
    user = User.query.get(current_user_id)
    print(user.email)
    if not user:
        return jsonify({"message": "User not found"}), 404
    slots_query = Slot.query.options(db.joinedload(Slot.booked_application))\
                               .filter_by(interviewer_email=user.email)\
                               .filter(Slot.is_booked.in_([0, 1])) \
                               .order_by(Slot.interview_time)\
                               .all()

    available_slots = slots_query
    
    # You might want to filter by job title/role as well if the user has a specific job they are hiring for
    # Example: If `user` has an associated job they are managing. This would depend on your user-job relationship.
    
    return render_template('view_slots.html', slots=available_slots, now=g.now  ) # Create this HTML template


@app.route('/applications/<int:application_id>/accept', methods=['POST'])
def accept_application_and_assign_slot(application_id):
    application = db.session.get(Application, application_id)
    if not application:
        return jsonify({"message": "Application not found"}), 404

   
    if application.status != "Pending":
        return jsonify({"message": "Application already processed."}), 400

    
    job = Job.query.get(application.job_id)
    if not job:
        return jsonify({"message": "Associated job not found."}), 404


    current_user_id = session.get('user_id')
    acting_user = db.session.get(User, current_user_id)
    print(current_user_id)
    if not acting_user or not acting_user.company_name:
        return jsonify({"message": "User's company information is missing for slot allocation."}), 400

   
    available_slot = Slot.query.filter(
        Slot.company_name == acting_user.company_name, # Filter by company accepting the application
        Slot.role == job.responsibilities, # Match the job title/role
        Slot.is_booked == False,
        Slot.interview_time > datetime.utcnow() # Only future slots
    ).order_by(Slot.interview_time.asc()).first() # Get the earliest available slot

    if not available_slot:
        # No slot available, maybe prompt for manual scheduling or offer to create one
        return jsonify({"message": "No available interview slots found for this role and company. Please add new slots."}), 404

    # Book the slot
    available_slot.is_booked = True
    available_slot.booked_by_application_id = application.id

    # Update application status
    application.status = "Interview Scheduled"

    db.session.execute(text("""
                INSERT INTO interview_schedule 
                (candidate_id, mode, interview_date, interviewer_name, interviewer_email, meeting_link, address)
                VALUES (:candidate_id, :mode, :interview_date, :interviewer_name, :interviewer_email, :meeting_link, :address)
            """), {
                "candidate_id": application.id,
                "mode": available_slot.mode,
                "interview_date": available_slot.interview_time,
                "interviewer_name": available_slot.interviewer_name,
                "interviewer_email":  available_slot.interviewer_email,
                "meeting_link": available_slot.meeting_link,
                "address":available_slot.address
    })

    try:
        db.session.commit()

        # Send emails to candidate and interviewer
        print("correct till here")
        send_schedule_email(
            application.applicant_email,
            available_slot.interview_time,
            available_slot.mode,
            available_slot.interviewer_name,
            available_slot.meeting_link,
            available_slot.address
            
        )
        send_schedule_email(
            available_slot.interviewer_email,
            available_slot.interview_time,
            available_slot.mode,
            available_slot.interviewer_name,
            available_slot.meeting_link,
            available_slot.address,
            is_interviewer=True
        )

        message = "Application accepted and interview scheduled."
       

        # Optionally, delete the old InterviewSchedule entry if it exists for this application
        # interview_schedule_entry = InterviewSchedule.query.filter_by(candidate_id=application.id).first()
        # if interview_schedule_entry:
        #     db.session.delete(interview_schedule_entry)
        #     db.session.commit() # Commit again after deleting

        return jsonify({"message": message, "slot_id": available_slot.id}), 200

    except Exception as e:
        db.session.rollback() # Rollback in case of error
        print(f"Error booking slot or sending email: {e}")
        return jsonify({"message": f"Failed to book slot or send emails. Error: {str(e)}"}), 500

# --- You might also want a route to delete a slot if it's no longer needed ---
@app.route('/slots/<int:slot_id>/delete', methods=['POST']) # Or DELETE method
def delete_slot(slot_id):
    slot = Slot.query.get(slot_id)
    if not slot:
        return jsonify({"message": "Slot not found"}), 404
    
    # Add authorization check here: Only owner company/admin can delete
    current_user_id = session.get('user_id')
    user = User.query.get(current_user_id)
    if not user or (user.company_name and user.company_name != slot.company_name) and user.role != 'admin':
        return jsonify({"message": "Unauthorized to delete this slot"}), 403

    if slot.is_booked:
        return jsonify({"message": "Cannot delete a booked slot. Unbook it first if necessary."}), 400

    db.session.delete(slot)
    db.session.commit()
    return jsonify({"message": "Slot deleted successfully"}), 200


# ==================== EXISTING ROUTES (PRESERVED) ====================
@app.route('/signup' , methods=['POST',"GET"])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        company_name = "User"
        role = "u"
        position = "user"
        if not name or not password:
            return jsonify({"message": "Name and password are required"}), 400

        existing_user = User.query.filter_by(name=name).first()
        if existing_user:
            return jsonify({"message": "Username already exists"}), 409

        new_user = User(name=name, email=email ,password=password, company_name=company_name, role=role,position=position)
        print("user created sucessfully ")
        db.session.add(new_user)
        db.session.commit()
        session['candidate_name'] = name
        session['candidate_email'] = email
        session['who'] ='user'
        return jsonify({"message": "Username signup"}), 200
    return render_template('signUp.html')


@app.route('/auth/google', methods=['POST'])
def google_auth():
    token = request.json.get('token')

    if not token:
        return jsonify({"message": "No Google token provided"}), 400

    try:
        # Verify the Google ID Token
        # It verifies the token's signature, issuer, and audience (your client ID)
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), os.getenv("GOOGLE_CLIENT_ID"))

        # Extract user information from the token
        google_id = idinfo['sub'] # Unique Google User ID
        email = idinfo.get('email')
        name = idinfo.get('name', email.split('@')[0] if email else 'User') # Default name if not provided
        password = "thub123"
        role = "u"
        position = "user"
        if not email:
            return jsonify({"message": "Google account did not provide an email address."}), 400

        # Check if user already exists in your database by Google ID
        user = User.query.filter_by(company_name=google_id).first()

        if user:
            # User exists via Google, log them in
            message = "Login"
        else:
            # Check if an account with this email already exists (e.g., from manual signup)
            existing_user_by_email = User.query.filter_by(email=email).first()
            if existing_user_by_email:
                # If email exists but google_id is null, link the Google ID to the existing account
                if not existing_user_by_email.google_id:
                    existing_user_by_email.google_id = google_id
                    db.session.commit()
                    user = existing_user_by_email
                    message = "Google account linked and logged in successfully!"
                else:
                    return jsonify({"message": "An account with this email already exists. Please log in normally or try linking your account."}), 409
            else:
                user = User(company_name=google_id, email=email, name=name,password=password,role=role,position=position)
                
                db.session.add(user)
                db.session.commit()
                message = "Signed up with Google successfully and logged in!"

        session['candidate_name'] = name
        session['candidate_email'] = email
        session['who'] ='user'
        return jsonify({"message": message, "user": user.to_dict()}), 200

    except ValueError as e:
        # Invalid token or other verification issues
        app.logger.error(f"Google token verification failed: {e}")
        return jsonify({"message": f"Authentication failed: Invalid token or client mismatch: {e}"}), 401
    except Exception as e:
        app.logger.error(f"An unexpected error occurred during Google auth: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred during Google authentication."}), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        password = data.get('password')

        if not name or not password:
            return jsonify({"message": "Name and password are required"}), 400

        user = User.query.filter_by(name=name).first()
        if not user or not user.check_password(password):
            return jsonify({"message": "Invalid username or password"}), 401

        
        if ( user.position == "interviewer"):
            session['role'] ='i'
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['name'] = user.company_name
            session['response'] = user.role
            session['email'] = user.email
            return jsonify({
            "message": "Login successful!",
            "name": user.name,
            "company_name": user.company_name,
            "email": user.email,
            "role": user.role,
            "position":user.position
        }), 200
        elif user.position == "manager": 
            session['role'] ='a'
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['name'] = user.company_name
            session['response'] = user.role
            session['email'] = user.email
            return jsonify({
            "message": "Login successful!",
            "name": user.name,
            "company_name": user.company_name,
            "email": user.email,
            "role": user.role,
            "position":user.position
        }), 200


        session['candidate_name'] = user.name
        session['candidate_email'] = user.email
        session['who'] ='user'
        return jsonify({
            "message": "Login successful!",
            "name": user.name,
            "company_name": user.company_name,
            "email": user.email,
            "role": user.role,
            "position":user.position
        }), 200
    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return jsonify({"message": "Successfully logged out"}), 200



# ==================== EXISTING ROUTES (KEEP ALL YOUR ORIGINAL ROUTES) ====================


@app.route('/applications/<int:app_id>/status', methods=['PUT'])
def update_application_status(app_id):
    application = db.session.get(Application, app_id)
    if not application:
        return jsonify({"message": "Application not found"}), 404
    data = request.get_json()
    new_status = data.get('status')
    if new_status == 'Rejected' and not application.rejection_email_sent:
        try:
            send_initial_rejection_email(application.applicant_email, application.applicant_name)
            application.rejection_email_sent = True
        except Exception as e:
            return jsonify({"message": str(e)}), 500
    application.status = new_status
    try:
        db.session.commit()
        return jsonify({"message": "Status updated"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

@app.route('/resumes/<filename>', methods=['GET'])
def serve_resume(filename):
    safe_filename = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename)

@app.route("/schedule", methods=["GET", "POST"])
def schedule_interview():
    if request.method == "POST":
        data = request.form
        try:
            # Step 1: Check if candidate already has an interview scheduled
            existing = db.session.execute(text("""
                SELECT 1 FROM interview_schedule WHERE candidate_id = :candidate_id
            """), {"candidate_id": data["candidate_id"]}).first()
            
            if existing:
                return "Interview already scheduled for this candidate.", 400

            # Step 2: Insert new interview schedule
            db.session.execute(text("""
                INSERT INTO interview_schedule 
                (candidate_id, mode, interview_date, interviewer_name, interviewer_email, meeting_link, address)
                VALUES (:candidate_id, :mode, :interview_date, :interviewer_name, :interviewer_email, :meeting_link, :address)
            """), {
                "candidate_id": data["candidate_id"],
                "mode": data["mode"],
                "interview_date": data["interview_datetime"],
                "interviewer_name": data["interviewer_name"],
                "interviewer_email": data["interviewer_email"],
                "meeting_link": data.get("meeting_link"),
                "address": data.get("address")
            })

            # Fetch candidate email
            result = db.session.execute(text("""
                SELECT applicant_email FROM application WHERE id = :candidate_id
            """), {"candidate_id": data["candidate_id"]}).mappings().first()

            if result:
                send_schedule_email(
                    result["applicant_email"],#fksdhgsufsdiugsdiugisdgdgisdgiusd
                    data["interview_datetime"],
                    data["mode"],
                    data["interviewer_name"],
                    data.get("meeting_link"),
                    data.get("address")
                )

            send_schedule_email(
                data["interviewer_email"],
                data["interview_datetime"],
                data["mode"],
                data["interviewer_name"],
                data.get("meeting_link"),
                data.get("address"),
                is_interviewer=True
            )

            db.session.commit()
            flash("Interview scheduled successfully and email sent.", "success")
        except Exception as e:
            db.session.rollback()
            return f"Error: {e}", 500

        return redirect("/view_applications.html")

    # Fetch candidates who have not been scheduled yet
    candidates = db.session.execute(text("""
        SELECT a.id, a.applicant_name
        FROM application a
        WHERE a.status = 'Accepted'
        AND a.id NOT IN (SELECT candidate_id FROM interview_schedule)
    """)).mappings().all()

    return render_template("schedule.html", candidates=candidates)

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        data = request.form

        # Prevent duplicate feedback using ORM
        existing = Feedback.query.filter_by(candidate_id=data["candidate_id"]).first()
        name = session.get('name')
        role = session.get('response')
        if existing:
            return "Feedback already submitted for this candidate.", 400

        try:
            # Create new feedback using ORM
            new_feedback = Feedback(
                candidate_id=int(data["candidate_id"]),
                comments=data["comments"],
                decision=data["decision"],
                communication_score=float(data["communication_score"]),
                technical_score=float(data["technical_score"]),
                problem_solving_score=float(data["problem_solving_score"])
            )
            db.session.add(new_feedback)
            application = Application.query.get(int(data['candidate_id']))
            if data['decision'] == "Accepted":
                if application:
                    accepted_candidate = AcceptedCandidate(
                        candidate_id=application.id,
                        applicant_name=application.applicant_name,
                        applicant_email=application.applicant_email,
                        company_name = name,
                        company_role =role
                    )
                    db.session.add(accepted_candidate)
                    application.status='Interview Completed'
            else:
                application.status = 'Rejected'
            slot = Slot.query.filter_by(
                booked_by_application_id=application.id,
                company_name=name,
                is_booked = 1,
                role=role
                ).first()

            slot.is_booked = 2
            db.session.commit()
            flash("Feedback submitted successfully.", "success")
            return redirect("/dashboard")

        except Exception as e:
            db.session.rollback()
            return f"Error: {e}", 500
@app.route('/fetch/feedback' ,methods=['POST','GET'])
def fetch():
    if request.method == "POST":
        try:
            data = request.get_json()
            id = data.get('app_id')
            if not id:
                return jsonify({'status':'Error','message':'Id is missign in the post request'}) ,500
            candidates = Application.query.get(id)
            return jsonify({'candidate_name':candidates.applicant_name, 'candidate_id':id}) ,200

        except Exception as e:
            print(f"Error fetching candidates: {e}")
            return render_template("error.html", message=f"An error occurred while fetching candidates: {e}")
    return render_template('feedback.html')

@app.route("/dashboard")
def dashboard():
    # Use ORM join instead of raw SQL
    feedback_data = db.session.query(
        Application.applicant_name,
        Feedback.decision,
        Feedback.comments,
        Feedback.communication_score,
        Feedback.technical_score,
        Feedback.problem_solving_score,
        Feedback.rejection_email_sent
    ).join(Application, Feedback.candidate_id == Application.id).all()
    
    return render_template("dashboard.html", feedback=feedback_data)



# [Include all other existing routes from the second file...]
# (Assessment, applications, schedule, feedback, dashboard routes remain the same)

@app.route('/assessment/<int:job_id>/<int:application_id>', methods=['GET'])
def assessment_page_route(job_id, application_id):
    job = db.session.get(Job, job_id)
    application = db.session.get(Application, application_id)
    if not job or not application or application.job_id != job.id:
        return render_template('main_page.html', message="Assessment Error."), 400
    return render_template('assessment_page.html')


@app.route('/mcqpage', methods=['GET'])
def mcq_page():
    """
    Simple MCQ page that follows the same dark theme as other pages.
    The page itself loads MCQ questions via JavaScript (demo data for now).
    """
    return render_template('mcqpage.html')


@app.route('/codingpage', methods=['GET'])
def coding_page():
    """
    Coding questions page with sidebar navigation.
    Frontend loads two coding questions via JavaScript (demo data for now),
    matching the expected API shape: { Questions: [ { question1: ..., question2: ... } ] }.
    """
    return render_template('codingpage.html')


@app.route('/mcq-login', methods=['GET'])
def mcq_login_page():
    """Simple MCQ Test login page (username & password only)."""
    return render_template('mcq_login.html')


@app.route('/coding-login', methods=['GET'])
def coding_login_page():
    """Simple Coding Test login page (username & password only)."""
    return render_template('coding_login.html')


@app.route('/interview-login', methods=['GET'])
def interview_login_page():
    """Interview login page (username & password)."""
    return render_template('interview_login.html')


@app.route('/interviewpage', methods=['GET'])
def interview_page():
    """Step-by-step voice interview page."""
    return render_template('interviewpage.html')


# ==================== MCQ / CODING TEST APIs (Gemini + Application) ====================

def _get_application_skills(application):
    """Return skills string from application: resume_skills or extract from resume_plain_text."""
    if application.resume_skills and application.resume_skills.strip():
        return application.resume_skills.strip()
    if application.resume_plain_text and application.resume_plain_text.strip():
        try:
            model = genai.GenerativeModel('gemini-2.5-flash')
            r = model.generate_content(
                f"From this resume text, extract a comma-separated list of technical skills (programming languages, tools, frameworks). Resume:\n\n{application.resume_plain_text[:4000]}\n\nReply with only the comma-separated skills, no other text."
            )
            return (r.text or "").strip() or "Programming, Problem Solving, General CS"
        except Exception as e:
            logging.warning(f"Gemini skills extraction failed: {e}")
    return "Programming, Problem Solving, General CS"


def _generate_mcq_questions_gemini(skills):
    """Generate 5 MCQ questions using Gemini. Returns list of {question, option1..4, answer}."""
    model = genai.GenerativeModel('gemini-2.5-flash')
    prompt = f"""You are a technical assessor. Generate exactly 5 multiple-choice questions (MCQs) based on these skills: {skills}.

    Difficulty mix: 40% easy (2 questions), 40% medium (2 questions), 20% hard (1 question). Order them: first easy, then medium, then hard.

For each question provide:
- question: the question text
- option1, option2, option3, option4: four options (exactly 4)
- answer: the correct option number as integer (1, 2, 3, or 4)

Respond with ONLY a valid JSON object in this exact format, no markdown or extra text:
{{"Questions": [{{"question": "...", "option1": "...", "option2": "...", "option3": "...", "option4": "...", "answer": 1}}, ...]}}"""
    try:
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text).strip()
            text = re.sub(r"\n?```\s*$", "", text).strip()
        data = json.loads(text)
        questions = data.get("Questions") or []
        return questions[:5]
    except Exception as e:
        logging.error(f"Gemini MCQ generation failed: {e}")
        return []


def _generate_coding_questions_gemini(skills):
    """Generate 1 coding question. Returns { question1 }."""
    model = genai.GenerativeModel('gemini-2.5-flash')
    prompt = f"""Generate exactly 1 coding question based on these skills: {skills}.

- The question should be EASY  (e.g. array/string or data structure manipulation).

Provide a clear problem statement, requirements, and one sample input/output if relevant.
It shouldnt be a big one it should be a easy a leet code question a dsa

Respond with ONLY a valid JSON object in this exact format, no markdown or extra text:
{{"Questions": [{{"question1": "Full question text..."}}]}}"""
    try:
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text).strip()
            text = re.sub(r"\n?```\s*$", "", text).strip()
        data = json.loads(text)
        qs = data.get("Questions") or []
        if qs:
            return qs[0]
        return {}
    except Exception as e:
        logging.error(f"Gemini coding questions generation failed: {e}")
        return {"question1": "Write a function that returns the sum of two numbers."}


@app.route('/api/mcq-login', methods=['POST'])
def api_mcq_login():
    """Validate user, find Application with status MCQ, get resume_skills, generate MCQs with Gemini, store in session, return questions."""
    data = request.get_json() or {}
    username = (data.get('username') or "").strip()
    password = data.get('password') or ""

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    user = User.query.filter_by(name=username).first()
    # if not user or not user.check_password(password):
    #     return jsonify({"success": False, "message": "Invalid username or password"}), 401

    application = Application.query.filter(
        db.or_(Application.applicant_name == user.name, Application.applicant_email == user.email),
        Application.status == 'MCQ'
    ).first()

    if not application:
        return jsonify({"success": False, "message": "No application found with status MCQ for this user"}), 403

    skills = _get_application_skills(application)
    questions = _generate_mcq_questions_gemini(skills)
    if not questions:
        return jsonify({"success": False, "message": "Failed to generate MCQ questions"}), 500

    session['mcq_application_id'] = application.id
    session['mcq_questions'] = questions
    session['mcq_user'] = username
    return jsonify({"success": True, "Questions": questions}), 200


@app.route('/api/mcq/questions', methods=['GET'])
def api_mcq_questions():
    """Return MCQ questions for current session (from mcq-login)."""
    if 'mcq_questions' not in session:
        return jsonify({"success": False, "message": "Not logged in for MCQ test"}), 401
    return jsonify({"success": True, "Questions": session['mcq_questions']}), 200


@app.route('/api/mcq-submit', methods=['POST'])
def api_mcq_submit():
    """Evaluate answers, store mcq_score, decide progression or rejection."""
    if 'mcq_application_id' not in session:
        return jsonify({"success": False, "message": "Session expired or not logged in"}), 401

    data = request.get_json() or {}
    answers = data.get('answers') or {}
    stored_questions = session.get('mcq_questions') or []

    application_id = session['mcq_application_id']
    application = db.session.get(Application, application_id)

    if not application:
        return jsonify({"success": False, "message": "Application not found"}), 404

    correct = 0
    total = len(stored_questions)
    for idx, q in enumerate(stored_questions):
        correct_opt = q.get('answer')  # 1-based from Gemini
        if correct_opt is None:
            continue
        user_opt = answers.get(str(idx))  # frontend sends 0-based option index
        if user_opt is not None and int(user_opt) + 1 == int(correct_opt):
            correct += 1

    score = (correct / total * 100) if total else 0
    application.mcq_score = round(score, 2)
    
    # Store MCQ questions and answers as JSON
    mcq_data = []
    for idx, q in enumerate(stored_questions):
        user_opt = answers.get(str(idx))
        # Extract options from option1, option2, option3, option4 fields
        options_list = [
            q.get('option1', ''),
            q.get('option2', ''),
            q.get('option3', ''),
            q.get('option4', '')
        ]
        options_list = [opt for opt in options_list if opt]  # Remove empty options
        
        user_answer_text = ""
        if user_opt is not None:
            opt_idx = int(user_opt)
            if 0 <= opt_idx < len(options_list):
                user_answer_text = options_list[opt_idx]
        
        correct_answer_idx = int(q.get('answer', 1)) - 1 if q.get('answer') else 0
        correct_answer_text = options_list[correct_answer_idx] if 0 <= correct_answer_idx < len(options_list) else ''
        
        mcq_data.append({
            "question": q.get('question', ''),
            "options": options_list,
            "correct_answer": correct_answer_text,
            "user_answer": user_answer_text,
            "is_correct": user_opt is not None and int(user_opt) + 1 == int(q.get('answer', 0)) if q.get('answer') else False
        })
    application.mcq_questions = json.dumps(mcq_data)

    # If score below threshold, reject with a gentle reason
    if score < 40:
        try:
            reason = _generate_rejection_reason(
                stage="MCQ",
                score=score,
                application=application,
                extra_context=f"MCQ score was {score:.2f} out of 100."
            )
            application.reason_for_rejection = reason
            application.status = "Rejected"
            db.session.commit()
            send_rejection_email(application.applicant_email, application.applicant_name, reason)
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    else:
        application.status = 'CODING'
        try:
            db.session.commit()
            send_email(
                application.applicant_email,
                "MCQ Test Result",
                f'''  Dear {application.applicant_name},

Congratulations!

You have successfully qualified in the MCQ assessment round.

Based on your performance, you are now invited to proceed to the Coding Round.

• Round: MCQ Assessment
• SCORE: {score:.2f} out of 100  
• Next Round Access Link: https://assessment-platform.com/mcq-login

If you have any technical issues during the assessment, contact us immediately at gangolamanikanta@gmail.com.

We wish you the best for the next stage.
                '''
            )
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500

    session.pop('mcq_questions', None)
    session.pop('mcq_application_id', None)
    session.pop('mcq_user', None)
    return jsonify({"success": True, "score": score, "correct": correct, "total": total}), 200


@app.route('/api/coding-login', methods=['POST'])
def api_coding_login():
    """Validate user, find Application with status CODING, get resume_skills, generate 2 coding questions (easy + medium)."""
    data = request.get_json() or {}
    username = (data.get('username') or "").strip()
    password = data.get('password') or ""

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    user = User.query.filter_by(name=username).first()
    # if not user or not user.check_password(password):
    #     return jsonify({"success": False, "message": "Invalid username or password"}), 401

    application = Application.query.filter(
        db.or_(Application.applicant_name == user.name, Application.applicant_email == user.email),
        Application.status == 'CODING'
    ).first()

    if not application:
        return jsonify({"success": False, "message": "No application found with status CODING for this user"}), 403

    skills = _get_application_skills(application)
    q_payload = _generate_coding_questions_gemini(skills)
    questions_list = [q_payload.get('question1', ''), q_payload.get('question2', '')]
    questions_list = [q for q in questions_list if q]

    if not questions_list:
        return jsonify({"success": False, "message": "Failed to generate coding questions"}), 500

    session['coding_application_id'] = application.id
    session['coding_questions'] = questions_list
    session['coding_user'] = username


    return jsonify({"success": True, "Questions": [{"question1": questions_list[0] if len(questions_list) > 0 else "", "question2": questions_list[1] if len(questions_list) > 1 else ""}]}), 200


@app.route('/api/coding/questions', methods=['GET'])
def api_coding_questions():
    """Return coding questions for current session."""
    if 'coding_questions' not in session:
        return jsonify({"success": False, "message": "Not logged in for coding test"}), 401
    qs = session['coding_questions']
    print('sending true')
    return jsonify({"success": True, "Questions": [{"question1": qs[0] if len(qs) > 0 else "", "question2": qs[1] if len(qs) > 1 else ""}]}), 200


def _evaluate_code_with_gemini(question_text, code_answer):
    """Use Gemini to score code answer (0-100) for a given question."""
    model = genai.GenerativeModel('gemini-2.5-flash')
    prompt = f"""You are a coding evaluator. Score the following code submission for the given problem from 0 to 100.

Problem:
{question_text[:2000]}

Submitted code:
{code_answer[:3000] if code_answer else '(empty)'}

Consider: correctness, readability, edge cases. Reply with ONLY a number between 0 and 100 (integer)."""
    try:
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        num = int(re.sub(r"[^0-9]", "", text) or "0")
        return max(0, min(100, num))
    except Exception as e:
        logging.warning(f"Gemini code evaluation failed: {e}")
        return 0


def _generate_rejection_reason(stage, score, application, extra_context=""):
    """Use Gemini to generate a short, encouraging rejection reason."""
    model = genai.GenerativeModel('gemini-2.5-flash')
    job = Job.query.get(application.job_id)
    job_title = job.title if job else "the role"
    prompt = f"""You are a kind and professional recruiter.

We rejected a candidate at the {stage} stage for {job_title}.
Their score was {score:.2f} out of 100.

Additional context:
{extra_context}

Write a SINGLE short sentence (max 30 words) that:
- briefly and neutrally explains what they should improve (skills, preparation, problem solving, communication etc.)
- stays positive and encouraging
- does NOT mention the exact score
- does NOT sound harsh or rude.

Return ONLY that one sentence, no other text."""
    try:
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        # Ensure it's a single line and not too long
        return text.split("\n")[0][:240]
    except Exception as e:
        logging.warning(f"Gemini rejection reason failed: {e}")
        return "Thank you for your effort. We encourage you to continue strengthening your skills and experience, and wish you the best for your future opportunities."


@app.route('/api/coding-submit', methods=['POST'])
def api_coding_submit():
    """Evaluate code answers with Gemini, store coding_score, decide progression or rejection."""
    if 'coding_application_id' not in session:
        return jsonify({"success": False, "message": "Session expired or not logged in"}), 401

    data = request.get_json() or {}
    answers = data.get('answers') or []
    questions = session.get('coding_questions') or []

    application_id = session['coding_application_id']
    application = db.session.get(Application, application_id)
    if not application:
        return jsonify({"success": False, "message": "Application not found"}), 404

    total_score = 0
    for i, ans in enumerate(answers):
        q_text = questions[i] if i < len(questions) else ""
        code = ans.get('code_answer', '') if isinstance(ans, dict) else ''
        total_score += _evaluate_code_with_gemini(q_text, code)

    coding_score = round(total_score / len(questions), 2) if questions else 0
    application.coding_score = coding_score
    
    # Store coding questions and answers as JSON
    coding_data = []
    for i, ans in enumerate(answers):
        q_text = questions[i] if i < len(questions) else ""
        code = ans.get('code_answer', '') if isinstance(ans, dict) else ''
        coding_data.append({
            "question": q_text,
            "user_answer": code
        })
    application.coding_questions = json.dumps(coding_data)

    if coding_score < 40:
        try:
            reason = _generate_rejection_reason(
                stage="CODING",
                score=coding_score,
                application=application,
                extra_context=f"Coding score was {coding_score:.2f} out of 100."
            )
            application.reason_for_rejection = reason
            application.status = "Rejected"
            db.session.commit()
            send_rejection_email(application.applicant_email, application.applicant_name, reason)
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    else:
        application.status = 'INTERVIEW'
        try:
            send_email(
                application.applicant_email,
                "Coding Test Result",
                f'''
  Dear {application.applicant_name},

Congratulations!

You have successfully qualified in the CODING assessment round .

Based on your performance, you are now invited to proceed to the Interview Round.

• Round: Coding Assessment  
• SCORE: {coding_score:.2f} out of 100
• Next Round Access Link: https://assessment-platform.com/interview-login

If you have any technical issues during the assessment, contact us immediately at gangolamanikanta@gmail.com.

We wish you the best for the next stage.
                '''
            )
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500

    session.pop('coding_questions', None)
    session.pop('coding_application_id', None)
    session.pop('coding_user', None)
    return jsonify({"success": True, "score": coding_score}), 200


# ==================== INTERVIEW (voice) APIs ====================

def _generate_interview_questions_gemini(github_summary, resume_skills):
    """Generate exactly 1 interview question based ONLY on github_summary and resume_skills."""
    model = genai.GenerativeModel('gemini-2.5-flash')
    github_part = (github_summary or "").strip()
    skills_part = (resume_skills or "").strip()
    if not github_part and not skills_part:
        skills_part = "General technical and problem-solving skills"
    prompt = f"""You are an interviewer. Generate exactly 1 interview question based ONLY on the following two inputs. Do not use any other knowledge.

1) GitHub summary:
{github_part if github_part else "(No GitHub summary provided)"}

2) Resume skills:
{skills_part}

Return ONLY a valid JSON array with exactly 1 question string, no other text. Example format:
["Single question text?"]"""
    try:
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text).strip()
            text = re.sub(r"\n?```\s*$", "", text).strip()
        arr = json.loads(text)
        if isinstance(arr, list) and len(arr) >= 1:
            return arr[:1]
        return []
    except Exception as e:
        logging.error(f"Gemini interview questions generation failed: {e}")
        return [
            "Tell us about a project from your GitHub or resume that you are proud of."
        ]


@app.route('/api/interview-login', methods=['POST'])
def api_interview_login():
    """Validate user, find Application with status INTERVIEW, ensure interview_questions exist (generate from github_summary + resume_skills if empty)."""
    data = request.get_json() or {}
    username = (data.get('username') or "").strip()
    password = data.get('password') or ""

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    user = User.query.filter_by(name=username).first()

    application = Application.query.filter(
        db.or_(Application.applicant_name == user.name, Application.applicant_email == user.email),
        Application.status == 'INTERVIEW'
    ).first()

    if not application:
        return jsonify({"success": False, "message": "No application found with status INTERVIEW for this user"}), 403

    # Load or generate interview questions (stored in DB column interview_questions)
    questions_list = []
    if application.interview_questions and application.interview_questions.strip():
        try:
            questions_list = json.loads(application.interview_questions)
            if not isinstance(questions_list, list):
                questions_list = []
        except Exception:
            questions_list = []

    if len(questions_list) < 1:
        github_summary = (application.github_summary or "").strip()
        skills = _get_application_skills(application)
        questions_list = _generate_interview_questions_gemini(github_summary, skills)
        if len(questions_list) < 1:
            return jsonify({"success": False, "message": "Failed to generate interview questions"}), 500
        application.interview_questions = json.dumps(questions_list[:1])
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500

    session['interview_application_id'] = application.id
    session['interview_questions'] = questions_list[:1]
    session['interview_user'] = username
    return jsonify({"success": True}), 200


@app.route('/api/interview/questions', methods=['GET'])
def api_interview_questions():
    """Return the interview question(s) (from session or from application in DB)."""
    if 'interview_application_id' not in session:
        return jsonify({"success": False, "message": "Not logged in for interview"}), 401

    application_id = session.get('interview_application_id')
    application = Application.query.get(application_id) if application_id else None
    questions = session.get('interview_questions')

    if not questions and application and application.interview_questions:
        try:
            questions = json.loads(application.interview_questions)
        except Exception:
            questions = []

    if not questions or len(questions) < 1:
        return jsonify({"success": False, "message": "Interview questions not available"}), 404

    return jsonify({"success": True, "Questions": questions[:1]}), 200


def _evaluate_interview_answer_gemini(question_text, answer_text):
    """Score a single interview Q&A from 0 to 100 using Gemini."""
    model = genai.GenerativeModel('gemini-2.5-flash')
    prompt = f"""You are an interview evaluator. Score the candidate's verbal answer from 0 to 100.

Question: {question_text[:1500]}

Candidate's answer: {answer_text[:2000] if answer_text else '(No answer or inaudible)'}

Consider relevance, clarity, and depth. Reply with ONLY a single integer between 0 and 100."""
    try:
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        num = int(re.sub(r"[^0-9]", "", text) or "0")
        return max(0, min(100, num))
    except Exception as e:
        logging.warning(f"Gemini interview evaluation failed: {e}")
        return 0


@app.route('/api/interview-submit', methods=['POST'])
def api_interview_submit():
    """Evaluate interview answer(s) with Gemini, store interview_score and possibly reject."""
    if 'interview_application_id' not in session:
        return jsonify({"success": False, "message": "Session expired or not logged in"}), 401

    data = request.get_json() or {}
    answers = data.get('answers') or []
    questions = session.get('interview_questions') or []

    application_id = session['interview_application_id']
    application = db.session.get(Application, application_id)
    if not application:
        return jsonify({"success": False, "message": "Application not found"}), 404

    total = 0
    for i, q_text in enumerate(questions):
        a_text = answers[i] if i < len(answers) and isinstance(answers[i], str) else (answers[i].get('answer', '') if i < len(answers) and isinstance(answers[i], dict) else '')
        total += _evaluate_interview_answer_gemini(q_text, a_text)

    interview_score = round(total / len(questions), 2) if questions else 0
    application.interview_score = interview_score
    
    # Store interview questions and answers as JSON
    interview_data = []
    for i, q_text in enumerate(questions):
        a_text = answers[i] if i < len(answers) and isinstance(answers[i], str) else (answers[i].get('answer', '') if i < len(answers) and isinstance(answers[i], dict) else '')
        interview_data.append({
            "question": q_text,
            "user_answer": a_text
        })
    application.interview_questions = json.dumps(interview_data)

    if interview_score < 40:
        try:
            reason = _generate_rejection_reason(
                stage="INTERVIEW",
                score=interview_score,
                application=application,
                extra_context=f"Interview score was {interview_score:.2f} out of 100."
            )
            application.reason_for_rejection = reason
            application.status = "Rejected"
            db.session.commit()
            send_rejection_email(application.applicant_email, application.applicant_name, reason)
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    else:
        try:
            db.session.commit()
            send_email(application.applicant_email,"Interview","Thank you for attending the interview, results will announcded shortly")
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500

    session.pop('interview_questions', None)
    session.pop('interview_application_id', None)
    session.pop('interview_user', None)
    return jsonify({"success": True, "score": interview_score}), 200


@app.route('/applications', methods=['POST'])
def get_filtered_applications():
    # if 'user_id' not in session:
    #     return jsonify({"message": "Unauthorized access. Please log in."}), 403

    data = request.get_json()
    name_filter = data.get('name')
    role_filter = data.get('role')
    print(name_filter)
    print(role_filter)
    
    if not name_filter and not role_filter:
        return jsonify({"error": "Missing 'name' or 'role' in request body."}), 400

    applications_query = Application.query

    applications_query = applications_query.filter(Job.is_open == 1)

    if name_filter:
        applications_query = applications_query.filter(Job.title.ilike(f'%{name_filter}%'))

    if role_filter:
        applications_query = applications_query.filter(Job.responsibilities.ilike(f'%{role_filter}%'))

    applications = applications_query.all()

    filtered_applications_list = []
    
    for app_obj in applications:
        job = db.session.get(Job, app_obj.job_id)
        if not job:
            continue

        filtered_applications_list.append({
            'id': app_obj.id,
            'job_id': app_obj.job_id,
            'job_title': job.title,
            'applicant_name': app_obj.applicant_name,
            'applicant_email': app_obj.applicant_email,
            'applicant_age': app_obj.applicant_age,
            'applicant_experience': app_obj.applicant_experience,
            'education': app_obj.education,
            'applied_at': app_obj.applied_at.isoformat(),
            'resume_path': app_obj.resume_path,
            'eligibility_score': app_obj.eligibility_score,
            'assessment_score': app_obj.assessment_score,
            'status': app_obj.status
        })

    print(filtered_applications_list)

    return jsonify(filtered_applications_list), 200


@app.route('/applicant_info', methods=['GET'])
def applicant_info():
    """Show applicants for a given job with round-based scoring view."""
    job_id = request.args.get('job_id', type=int)
    if not job_id:
        return render_template('error.html', message="Missing job_id for applicant info"), 400

    job = Job.query.get(job_id)
    if not job:
        return render_template('error.html', message="Job not found"), 404

    applications = Application.query.filter_by(job_id=job_id).all()

    def base_score(app):
        # Aggregate all known score components; treat None as 0
        components = [
            app.resume_score or 0,
            app.leetcode_score or 0,
            app.github_score or 0,
            app.eligibility_score or 0,
            app.mcq_score or 0,
            app.coding_score or 0,
            app.interview_score or 0,
        ]
        return round(sum(components), 2)

    def serialize(app):
        return {
            "id": app.id,
            "job_id": app.job_id,
            "name": app.applicant_name,
            "email": app.applicant_email,
            "resume_score": app.resume_score,
            "leetcode_score": app.leetcode_score,
            "github_score": app.github_score,
            "eligibility_score": app.eligibility_score,
            "mcq_score": app.mcq_score,
            "coding_score": app.coding_score,
            "interview_score": app.interview_score,
            "score": base_score(app),
            "offer_status": app.offer_status,
        }

    # Prepare round-wise lists, already filtered/sorted
    round1 = [
        a for a in applications
        if a.resume_score is not None
        and a.leetcode_score is not None
        and a.github_score is not None
        and a.eligibility_score is not None
    ]
    round1 = sorted(round1, key=base_score, reverse=True)

    round2 = [
        a for a in applications
        if a.mcq_score is not None
    ]
    round2 = sorted(round2, key=base_score, reverse=True)

    round3 = [
        a for a in applications
        if a.coding_score is not None
    ]
    round3 = sorted(round3, key=base_score, reverse=True)

    round4 = [
        a for a in applications
        if a.interview_score is not None
    ]
    round4 = sorted(round4, key=base_score, reverse=True)

    context = {
        "job": job,
        "round1": [serialize(a) for a in round1],
        "round2": [serialize(a) for a in round2],
        "round3": [serialize(a) for a in round3],
        "round4": [serialize(a) for a in round4],
    }
    return render_template('admins/applicant_info.html', **context)


@app.route('/info/<int:application_id>/<student_name>', methods=['GET'])
def applicant_detail(application_id, student_name):
    """Detail page for a single applicant with round-by-round breakdown."""
    application = Application.query.get_or_404(application_id)
    
    # Parse questions and answers from JSON fields
    mcq_data = []
    coding_data = []
    interview_data = []
    
    if application.mcq_questions:
        try:
            mcq_data = json.loads(application.mcq_questions)
        except:
            mcq_data = []
    
    if application.coding_questions:
        try:
            coding_data = json.loads(application.coding_questions)
        except:
            coding_data = []
    
    if application.interview_questions:
        try:
            interview_data = json.loads(application.interview_questions)
        except:
            interview_data = []
    
    return render_template('admins/applicant_detail.html', 
                         application=application,
                         mcq_data=mcq_data,
                         coding_data=coding_data,
                         interview_data=interview_data)


@app.route('/offers/send-top', methods=['POST'])
def send_top_offers():
    """Mark top K candidates for a job as offer_sent and email them."""
    data = request.get_json() or {}
    job_id = data.get('job_id')
    if not job_id:
        return jsonify({"message": "job_id is required"}), 400

    job = Job.query.get(job_id)
    if not job:
        return jsonify({"message": "Job not found"}), 404

    applications = Application.query.filter_by(job_id=job_id).filter(
        Application.interview_score.isnot(None)
    ).all()

    if not applications:
        return jsonify({"message": "No candidates with interview_score found for this job"}), 400

    def base_score(app):
        components = [
            app.resume_score or 0,
            app.leetcode_score or 0,
            app.github_score or 0,
            app.eligibility_score or 0,
            app.mcq_score or 0,
            app.coding_score or 0,
            app.interview_score or 0,
        ]
        return round(sum(components), 2)

    # Sort best to worst
    applications_sorted = sorted(applications, key=base_score, reverse=True)

    k = job.number_of_positions or 0
    if k <= 0:
        return jsonify({"message": "Job has no number_of_positions configured"}), 400

    selected = applications_sorted[:k]
    updated_ids = []

    for app_obj in selected:
        # Skip if already marked as offer_sent
        if app_obj.offer_status == "offer_sent":
            continue

        app_obj.offer_status = "offer_sent"
        updated_ids.append(app_obj.id)

        # Send personalized offer email
        subject = f"Job Offer - {job.title}"
        body = (
            f"Dear {app_obj.applicant_name},\n\n"
            f"Congratulations! Based on your performance in all rounds for the role '{job.title}', "
            f"we are pleased to move forward with an offer.\n\n"
            f"Our team will share further details with you shortly.\n\n"
            f"Best regards,\n"
            f"Recruitment Team"
        )
        try:
            send_email(app_obj.applicant_email, subject, body)
        except Exception as e:
            # Log but don't fail the whole batch
            logging.error(f"Failed to send offer email to {app_obj.applicant_email}: {e}")

    if not updated_ids:
        return jsonify({"message": "No new candidates were updated (already offer_sent)"}), 200

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Failed to update offer_status in database: {e}"}), 500

    return jsonify({"message": "Offers sent successfully", "updated_ids": updated_ids}), 200

# ==================== BACKGROUND TASKS ====================

def send_feedback_rejections():
    with app.app_context():
        rejected_feedback = db.session.query(
            Feedback.feedback_id,
            Feedback.comments,
            Application.applicant_email,
            Application.applicant_name
        ).join(Application, Feedback.candidate_id == Application.id)\
        .filter(Feedback.decision == 'Rejected')\
        .filter((Feedback.rejection_email_sent.is_(None)) | (Feedback.rejection_email_sent == False)).all()
        
        for feedback in rejected_feedback:
            try:
                feedback_obj = db.session.get(Feedback, feedback.feedback_id)
                if feedback_obj.rejection_email_sent:
                    continue
                    
                send_rejection_email(feedback.applicant_email, feedback.applicant_name, feedback.comments)
                
                feedback_obj.rejection_email_sent = True
                db.session.commit()
                print(f"✅ Sent rejection email to {feedback.applicant_name} ({feedback.applicant_email})")
                
            except Exception as e:
                print(f"❌ Error sending feedback rejection to {feedback.applicant_name}: {e}")
                db.session.rollback()

def send_reminders():
    with app.app_context():
        now = datetime.now()

        interviews = db.session.query(
            InterviewSchedule.id,
            InterviewSchedule.interview_date,
            InterviewSchedule.candidate_id,
            InterviewSchedule.mode,
            InterviewSchedule.interviewer_name,
            InterviewSchedule.interviewer_email,
            InterviewSchedule.meeting_link,
            InterviewSchedule.address,
            InterviewSchedule.reminder_1day_sent,
            InterviewSchedule.reminder_1hour_sent,
            Application.applicant_email,
            Application.applicant_name
        ).join(Application, InterviewSchedule.candidate_id == Application.id)\
        .filter(InterviewSchedule.interview_date > now).all()
        
        for interview in interviews:
            interview_time = interview.interview_date
            time_diff = interview_time - now
            
            try:
                interview_obj = db.session.get(InterviewSchedule, interview.id)

                if time_diff <= timedelta(days=1) and time_diff > timedelta(hours=23):
                    if not interview_obj.reminder_1day_sent:
                        send_reminder_email(interview.applicant_email, interview_time, interview.applicant_name,
                                            interview.mode, interview.meeting_link, interview.address)

                        send_reminder_email(interview.interviewer_email, interview_time, interview.interviewer_name,
                                            interview.mode, interview.meeting_link, interview.address, True)

                        interview_obj.reminder_1day_sent = True
                        db.session.commit()
                        print(f"✅ Sent 1-day reminder for {interview.applicant_name}")

                elif time_diff <= timedelta(hours=1) and time_diff > timedelta(minutes=30):
                    if not interview_obj.reminder_1hour_sent:
                        send_reminder_email(interview.applicant_email, interview_time, interview.applicant_name,
                                            interview.mode, interview.meeting_link, interview.address)

                        send_reminder_email(interview.interviewer_email, interview_time, interview.interviewer_name,
                                            interview.mode, interview.meeting_link, interview.address, True)

                        interview_obj.reminder_1hour_sent = True
                        db.session.commit()
                        print(f"✅ Sent 1-hour reminder for {interview.applicant_name}")

            except Exception as e:
                print(f"❌ Reminder error for {interview.applicant_name}: {e}")
                db.session.rollback()

# Schedule background tasks
schedule.every(2).minutes.do(send_feedback_rejections)
schedule.every(2).minutes.do(send_reminders)
schedule.every(5).minutes.do(process_job_offers)  # Process offers every 5 minutes

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

# Start background scheduler
threading.Thread(target=run_scheduler, daemon=True).start()

if __name__ == '__main__':
    app.run(debug=True, port=5000)