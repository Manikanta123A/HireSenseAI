# my_tiny_app/routes/general.py
from flask import Blueprint, render_template, session, jsonify, request
from models import Application, Job, db
from sqlalchemy.orm import selectinload
from sqlalchemy import desc
from email_utils import send_email

# Create a blueprint for general routes
user_bp = Blueprint('user_bp', __name__)

@user_bp.route('/')
def home():
    return render_template('users/userHome.html')


@user_bp.route('/applications', methods=['GET'])
def get_user_applications():
    """
    API endpoint to retrieve all job applications for the logged-in user.
    It fetches related job, interview, feedback, and job offer data.
    """
    user_email = session.get('candidate_email')
    user_name = session.get('candidate_name')

    if not user_email:
        # If no user is logged in, return an error. Frontend should redirect to login.
        return jsonify({'message': 'Unauthorized: Please log in to view applications.'}), 401
    
    try:
        # Query applications for the logged-in user's email
        applications = Application.query.filter_by(applicant_email=user_email).options(
            selectinload(Application.job),
            selectinload(Application.interview_schedule),
        ).order_by(desc(Application.applied_at)).all()

        applications_data = []
        for app in applications:
            app_dict = {
                "id": app.id,
                "job_id": app.job_id,
                "job_title": app.job.title if app.job else "N/A",
                "status": app.status,
                "applied_at": app.applied_at.isoformat() if app.applied_at else None,
                "applicant_name": app.applicant_name,
                "applicant_email": app.applicant_email,
                "resume_score": app.resume_score,
                "leetcode_score": app.leetcode_score,
                "github_score": app.github_score,
                "eligibility_score": app.eligibility_score,
                "mcq_score": app.mcq_score,
                "coding_score": app.coding_score,
                "interview_score": app.interview_score,
                "offer_status": app.offer_status,
            }

            # Basic interview schedule info (optional)
            if app.interview_schedule:
                app_dict["interview_details"] = [s.to_dict() for s in app.interview_schedule]
            else:
                app_dict["interview_details"] = []

            applications_data.append(app_dict)

        return jsonify(
            {
                "applications": applications_data,
                "user_name": user_name,
                "total_applications": len(applications_data),
            }
        ), 200

    except Exception as e:
        # Log the error for debugging
        print(f"Error fetching applications: {str(e)}")
        return jsonify({'message': 'Error fetching applications. Please try again later.'}), 500


@user_bp.route('/myapp')
def fetchi():
    return render_template('users/userapplication.html')


@user_bp.route('/offer/decision', methods=['POST'])
def offer_decision():
    """Candidate accepts or rejects an offer. On reject, pass offer to next best pending candidate."""
    user_email = session.get('candidate_email')
    if not user_email:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json() or {}
    application_id = data.get('application_id')
    decision = (data.get('decision') or "").lower()

    if not application_id or decision not in ("accept", "reject"):
        return jsonify({"message": "application_id and valid decision are required"}), 400

    app_obj = Application.query.get_or_404(application_id)

    # Ensure this application belongs to the logged-in candidate
    if app_obj.applicant_email != user_email:
        return jsonify({"message": "Forbidden"}), 403

    job = Job.query.get(app_obj.job_id)
    if not job:
        return jsonify({"message": "Job not found"}), 404

    if decision == "accept":
        app_obj.offer_status = "accepted"
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Failed to update offer status: {e}"}), 500

        return jsonify({"message": "Offer accepted"}), 200

    # decision == "reject"
    app_obj.offer_status = "declined"

    def base_score(a):
        components = [
            a.resume_score or 0,
            a.leetcode_score or 0,
            a.github_score or 0,
            a.eligibility_score or 0,
            a.mcq_score or 0,
            a.coding_score or 0,
            a.interview_score or 0,
        ]
        return round(sum(components), 2)

    # Find next best candidate for same job with pending offer
    candidates = (
        Application.query.filter_by(job_id=app_obj.job_id)
        .filter(
            Application.interview_score.isnot(None),
            Application.offer_status == "pending",
        )
        .all()
    )

    next_candidate = None
    if candidates:
        candidates_sorted = sorted(candidates, key=base_score, reverse=True)
        next_candidate = candidates_sorted[0]

    promoted_id = None
    if next_candidate:
        next_candidate.offer_status = "offer_sent"
        promoted_id = next_candidate.id

        subject = f"Job Offer - {job.title}"
        body = (
            f"Dear {next_candidate.applicant_name},\n\n"
            f"Based on your performance in all rounds for the role '{job.title}', "
            f"we are pleased to move forward with an offer.\n\n"
            f"Our team will share further details with you shortly.\n\n"
            f"Best regards,\n"
            f"Recruitment Team"
        )
        try:
            send_email(next_candidate.applicant_email, subject, body)
        except Exception as e:
            print(f"Failed to send email to next candidate {next_candidate.applicant_email}: {e}")

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Failed to update offer statuses: {e}"}), 500

    return jsonify(
        {
            "message": "Offer declined and passed to next candidate" if promoted_id else "Offer declined",
            "next_candidate_id": promoted_id,
        }
    ), 200