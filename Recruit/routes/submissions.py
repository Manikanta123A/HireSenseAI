from flask import Blueprint, render_template, request, jsonify, current_app as app
from models import db, Job, Application
import PyPDF2, json, re, os, uuid
import google.generativeai as genai
from werkzeug.utils import secure_filename
import requests
import google.generativeai as genai
from PyPDF2 import PdfReader
import re
import json
import datetime
from email_utils import send_email

# Blueprint setup
submit_bp = Blueprint('submit_bp', __name__)

# Gemini config
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 8192,
}

# Allowed file types
ALLOWED_EXTENSIONS = {'pdf'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Resume text extraction




def gh_username(url):
    m = re.search(r"github\.com/([^/]+)", url)
    return m.group(1) if m else None


def fetch_github(username):

    user = requests.get(f"https://api.github.com/users/{username}").json()
    repos = requests.get(
        f"https://api.github.com/users/{username}/repos?per_page=100"
    ).json()

    if "message" in user:
        return {}

    total_stars=0
    total_forks=0
    watchers=0
    langs={}
    topics=[]
    active=0
    now=datetime.datetime.utcnow()

    for r in repos:
        total_stars+=r.get("stargazers_count",0)
        total_forks+=r.get("forks_count",0)
        watchers+=r.get("watchers_count",0)

        lang=r.get("language")
        if lang:
            langs[lang]=langs.get(lang,0)+1

        topics+=r.get("topics",[])

        upd=r.get("updated_at")
        if upd:
            dt=datetime.datetime.strptime(upd,"%Y-%m-%dT%H:%M:%SZ")
            if (now-dt).days<120:
                active+=1

    created=datetime.datetime.strptime(
        user["created_at"],"%Y-%m-%dT%H:%M:%SZ"
    )

    return {
        "repos":user.get("public_repos",0),
        "followers":user.get("followers",0),
        "account_age_years":(now-created).days//365,
        "total_stars":total_stars,
        "total_forks":total_forks,
        "watchers":watchers,
        "active_repos":active,
        "top_languages":sorted(langs,key=langs.get,reverse=True)[:5],
        "topics":list(set(topics))[:10]
    }


# ---------------- LEETCODE ----------------

def lc_username(url):
    m=re.search(r"leetcode\.com/(?:u/)?([^/]+)/?",url)
    return m.group(1) if m else None


def fetch_leetcode(username):

    query="""
    query($username: String!) {
      matchedUser(username: $username){
        submitStatsGlobal{
          acSubmissionNum{
            difficulty
            count
          }
        }
      }
    }
    """

    r=requests.post(
        "https://leetcode.com/graphql",
        json={"query":query,"variables":{"username":username}}
    )

    stats=r.json()["data"]["matchedUser"]["submitStatsGlobal"]["acSubmissionNum"]
    m={s["difficulty"]:s["count"] for s in stats}

    return {
        "total":m.get("All",0),
        "easy":m.get("Easy",0),
        "medium":m.get("Medium",0),
        "hard":m.get("Hard",0)
    }


# ---------------- GEMINI EVAL ----------------

def evaluate_all(resume, gh, lc, job_title, job_desc):

    prompt=f"""
You are an expert technical recruiter.

Your job is to evaluate a candidate based on the JOB ROLE.

First, infer what matters most for this role.

Examples:
- SDE/Backend/Frontend → LeetCode + GitHub matter more
- Data Scientist/ML → Projects + skills + GitHub matter more
- Manager/Senior roles → Resume/experience matter more
- Research roles → Depth + GitHub + hard problems matter

STEP 1:
Decide weight distribution:
- resume_weight
- github_weight
- leetcode_weight

Weights must sum to 1.0

STEP 2:
Score each independently (0–100).

STEP 3:
Compute final_overall_score using your weights.

--------------------

JOB TITLE:
{job_title}

JOB DESCRIPTION:
{job_desc}

--------------------

CANDIDATE DATA

Resume:
{resume}

GitHub:
{gh}

LeetCode:
{lc}

--------------------

Return ONLY valid JSON:

{{
"weights": {{
    "resume": float,
    "github": float,
    "leetcode": float
}},
"resume_score": int,
"github_score": int,
"leetcode_score": int,
"final_overall_score": int,
"skills": ["list skills from resume"]
}}

Be realistic and strict like a FAANG recruiter.
"""

    try:
        model=genai.GenerativeModel('gemini-2.5-flash', generation_config=generation_config)
        response = model.generate_content(prompt)

        return response

    except:
        return fallback(resume,gh,lc,job_desc)


# ---------------- FALLBACK ----------------

def fallback(resume,gh,lc,job_desc):

    resume_l=resume.lower()
    jd=job_desc.lower()

    skills=[]
    keywords=["python","java","sql","ml","ai","javascript","react","data"]

    for k in keywords:
        if k in resume_l:
            skills.append(k.capitalize())

    # job match boost
    match=sum(1 for k in keywords if k in jd and k in resume_l)

    resume_score=min(100,50+len(skills)*6+match*5)
    github_score=min(100,gh.get("repos",0)*4+gh.get("total_stars",0))
    leetcode_score=min(100,lc["total"])

    final=int(
        resume_score*0.4+
        github_score*0.3+
        leetcode_score*0.3
    )

    return {
        "resume_score":resume_score,
        "github_score":github_score,
        "leetcode_score":leetcode_score,
        "final_overall_score":final,
        "skills":skills
    }


def extract_text_from_pdf(pdf_file_object):
    text = ""
    try:
        reader = PyPDF2.PdfReader(pdf_file_object)
        for page in reader.pages:
            text += page.extract_text() or ""
    except Exception as e:
        print(f"Error extracting text from PDF: {e}")
        text = "Error extracting resume text."
    return text

# Submit application route
@submit_bp.route('/submit_application', methods=['POST'])
def submit_application():
    print("Received request to submit_application!") 
    job_id = request.form.get('jobId')
    name = request.form.get('name')
    applicant_age_str = request.form.get('age')
    email = request.form.get('email')
    applicant_experience = request.form.get('experience')
    education = request.form.get('education')
    resume_file = request.files.get('resume')
    leetcode = request.form.get('leetcode')
    Github = request.form.get('github')
    Linkedin = request.form.get('linkedin')

    if not all([job_id, name, applicant_age_str, email, applicant_experience, education, resume_file,leetcode, Github, Linkedin]):
        return jsonify({"message": "Missing required application fields."}), 400

    job = db.session.get(Job, job_id)
    if not job:
        return jsonify({"message": "Job not found."}), 404

    if resume_file and allowed_file(resume_file.filename):
        filename = secure_filename(f"{uuid.uuid4()}_{resume_file.filename}")
        resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        resume_file.save(resume_path)

        with open(resume_path, 'rb') as f:
            resume_plain_text = extract_text_from_pdf(f)

        job_keywords = set(re.findall(r'\b\w+\b', job.description.lower()))
        resume_keywords = set(re.findall(r'\b\w+\b', resume_plain_text.lower()))
        common_keywords = len(job_keywords.intersection(resume_keywords))
        eligibility_score = (common_keywords / len(job_keywords)) * 100 if len(job_keywords) > 0 else 0.0

        applicant_age = int(applicant_age_str) if applicant_age_str.isdigit() else None


        gh=fetch_github(gh_username(Github))

        lc=fetch_leetcode(lc_username(leetcode))

        response=evaluate_all(resume_plain_text,gh,lc,job.title,job.description)
        gemini_output_text=response.text.strip()

        json_match = re.search(r"```json\s*(\{.*?})\s*```", gemini_output_text, re.DOTALL)
        gemini_output_json_str = json_match.group(1) if json_match else gemini_output_text
        gemini_output = json.loads(gemini_output_json_str)



        leetcode_score = float(gemini_output.get('leetcode_score', 0.0))
        github_score = float( gemini_output.get('github_score', 0.0))
        final_score = float(gemini_output.get('final_overall_score', 0.0))  
        resume_score = float(gemini_output.get('resume_score',0.0))
        skills = gemini_output.get('skills', [])
        skills = ''.join(skills)




        new_application = Application(
            job_id=job_id,
            applicant_name=name,
            applicant_age=applicant_age,
            applicant_email=email,
            leetcode=leetcode,
            Github=Github,
            LinkedIn=Linkedin,
            applicant_experience=applicant_experience,
            education=education,
            resume_path=filename,
            resume_plain_text=resume_plain_text,
            eligibility_score=final_score,
            leetcode_score=leetcode_score,
            github_score=github_score,
            resume_score = resume_score,
            resume_skills = skills,
            status='MCQ'
        )
        db.session.add(new_application)
        try:
            db.session.commit()
            send_email(email,'Next Round', 'Qualified for MCQ round , please use below link for it  http://localhost:5000/coding-login')
            return jsonify({
                "message": "Application submitted successfully! Please proceed to assessment.",
                "job_id": job_id,
                "application_id": new_application.id,
            }), 201
            
        except Exception as e:
            db.session.rollback()
            if os.path.exists(resume_path):
                os.remove(resume_path)
            return jsonify({"message": f"Error submitting application: {str(e)}"}), 500
    else:
        return jsonify({"message": "Invalid file type. Only PDF is allowed."}), 400
    








    
















































# Submit assessment route
@submit_bp.route('/', methods=['POST'])
def submit_assessment(job_id, application_id):
    application = db.session.get(Application, application_id)
    job = db.session.get(Job, job_id)

    if not application or not job:
        return jsonify({"message": "Application or Job not found."}), 404

    data = request.get_json()
    user_answers = data.get('answers', [])

    print("submitted assesment")

    job_description = job.description
    job_qualifications = job.qualifications
    job_responsibilities = job.responsibilities
    min_assessment_score = job.min_assesment_score
    resume_text = application.resume_plain_text
    job_assessment_questions = json.loads(job.assessment_questions) if job.assessment_questions else []

    formatted_user_answers = []
    for ua in user_answers:
        idx = ua.get('question_index')
        answer = ua.get('answer')
        if 0 <= idx < len(job_assessment_questions):
            question_text = job_assessment_questions[idx]
            formatted_user_answers.append(f"Question: {question_text}\nAnswer: {answer}")

    user_answers_str = "\\n\\n".join(formatted_user_answers)

    gemini_prompt = [
        f"""
        You are an advanced AI expert in resume screening and candidate-job matching.

        You will receive a job description and a resume. Analyze the resume in detail against the job description and provide a comprehensive evaluation.
       Score the resume out of 100 based on:
        - skills, qualifications, achievements, certifications, projects, location, experience, resume_quality

        Also evaluate assessment answers (provided below) on a 0–100 scale.

        also extrct the good summary of the resume in Resume Summary field
        If the name in the resume and the name in the applicant_anme are not similar then  return a score of 0.

        Format:
        {{
          "gemini_score": 85.5,
          "assessment_score": 86.7,
          "reasoning": "Strong alignment with qualifications and good answers.",
          "Resume Summary": "The candidate has relevant experience and skills.",
        }}

        Job Title: {job.title}
        Description: {job_description}
        Qualifications: {job_qualifications}
        Responsibilities: {job_responsibilities}

        Applicant:
        - Name: {application.applicant_name}
        - Email: {application.applicant_email}
        - Age: {application.applicant_age}
        - Experience: {application.applicant_experience}
        - Education: {application.education}
        - Resume: {resume_text[:3000]}
        dont direct match the name strings in the resume and applicant_name , just check the similarity and if it looks complety differetn then return 0 else behave normally 
        Name in the Resume should matcht the applicant_name other wise return 0 score
        Assessment Answers:
        {user_answers_str}
        if the name in the resume and the name in the applicant_name do not match, return a score of 0.
        """
    ]

    try:
        model = genai.GenerativeModel('gemini-2.5-flash', generation_config=generation_config)
        response = model.generate_content(gemini_prompt)
        gemini_output_text = response.text.strip()

        json_match = re.search(r"```json\s*(\{.*?})\s*```", gemini_output_text, re.DOTALL)
        gemini_output_json_str = json_match.group(1) if json_match else gemini_output_text
        gemini_output = json.loads(gemini_output_json_str)

        gemini_score = float(gemini_output.get('gemini_score', 0.0))
        assessment_score = float(gemini_output.get('assessment_score', 0.0))
        print("assesmnet score :", assessment_score)
        # if assessment_score < min_assessment_score:
        #     db.session.delete(application)
        #     db.session.commit()
        #     return jsonify({
        #         "message": "Application rejected. Assessment score below minimum threshold.",
        #         "assessment_score": assessment_score,
        #         "min_assessment_score":min_assessment_score
        #     }), 200

        application.eligibility_score = gemini_score
        application.assessment_score = assessment_score
        application.status = "Pending"
        db.session.commit()

        return jsonify({
            "message": "Assessment submitted and scored successfully!",
            "gemini_score": gemini_score,
            "assessment_score": assessment_score
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"[Gemini Error] {e}")
        return jsonify({"message": f"Error during Gemini evaluation: {str(e)}"}), 500
