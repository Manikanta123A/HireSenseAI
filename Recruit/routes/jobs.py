# my_tiny_app/routes/general.py
from flask import Blueprint,render_template,request,jsonify,session
from models import Job, db
import json
from datetime import datetime

# Create a blueprint for general routes
job_bp = Blueprint('job_bp', __name__)


@job_bp.route('/', methods=['POST', 'GET'])
def handle_jobs():
    if request.method == 'POST':
        title = request.form.get('jobTitle')
        description = request.form.get('jobDescription')
        qualifications = request.form.get('qualifications')
        responsibilities = request.form.get('responsibilities')
        required_experience = request.form.get('requiredExperience')
        number_of_positions = request.form.get('number_of_positions')
        deadline_str = request.form.get('deadline')  
        try:
            deadline = datetime.fromisoformat(deadline_str)
        except ValueError:
            return jsonify({"message": "Invalid date/time format"}), 400

        if not all([title, description, qualifications, responsibilities, required_experience,number_of_positions,deadline]):
            return jsonify({"message": "Missing required fields."}), 400


        new_job = Job(
            title=title,
            description=description,
            qualifications=qualifications,
            responsibilities=responsibilities,
            required_experience=required_experience,
            number_of_positions=number_of_positions,
            deadline=deadline
        )
        db.session.add(new_job)
        try:
            db.session.commit()
            return jsonify({"message": "Job posted successfully!", "job_id": new_job.id}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Error posting job: {str(e)}"}), 500

    elif request.method == 'GET':
        jobs = Job.query.filter_by(is_open=0).all() 
        jobs_list = []
        for job in jobs:
            jobs_list.append({
                'id': job.id,
                'title': job.title,
                'description': job.description,
                'qualifications': job.qualifications,
                'responsibilities': job.responsibilities,
                'posted_at': job.posted_at.isoformat(),
                'required_experience': job.required_experience,
            })
        return jsonify(jobs_list), 200


@job_bp.route('/job_post.html')
def job_postings_page():
    return render_template('Jobs/job_post.html')

#Posting a JOb
@job_bp.route('/post_job.html')
def post_job_page():
    return render_template('Jobs/job_form.html')

#editing a job
@job_bp.route('/edit_job.html')
def edit_job_page():
    return render_template('Jobs/edit_job.html')


#handling the job edits
@job_bp.route('/<int:job_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_job(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        return jsonify({"message": "Job not found"}), 404

    if request.method == 'GET':
        return jsonify({
            'id': job.id,
            'title': job.title,
            'description': job.description,
            'qualifications': job.qualifications,
            'responsibilities': job.responsibilities,
            'posted_at': job.posted_at.isoformat(),
            'required_experience': job.required_experience,
            'number_of_positions':job.number_of_positions
        }), 200

    elif request.method == 'PUT':
        title = request.form.get('jobTitle')
        description = request.form.get('jobDescription')
        qualifications = request.form.get('qualifications')
        responsibilities = request.form.get('responsibilities')
        required_experience = request.form.get('requiredExperience')
        number_of_positions = request.form.get('number_of_positions')

        if not all([title, description, qualifications, responsibilities, required_experience]):
            return jsonify({"message": "Missing required fields."}), 400
        
        job.title = title
        job.description = description
        job.qualification = qualifications
        job.responsibilities = responsibilities
        job.required_experience = required_experience
        job.number_of_positions = number_of_positions
        try:
            db.session.commit()
            return jsonify({"message": "Job updated successfully!"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Error updating job: {str(e)}"}), 500

    elif request.method == 'DELETE':
        try:
            job.is_open= 1
            db.session.commit()
            return jsonify({"message": "Job deleted successfully!"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"Error deleting job: {str(e)}"}), 500
