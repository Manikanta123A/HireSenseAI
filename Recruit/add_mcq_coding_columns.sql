-- Run this once to add MCQ/Coding/Interview columns to the application table (if they don't exist).
-- MySQL: run each line separately; if a column already exists, that statement will error (skip it).

ALTER TABLE application ADD COLUMN resume_skills TEXT NULL;
ALTER TABLE application ADD COLUMN mcq_score FLOAT NULL;
ALTER TABLE application ADD COLUMN coding_score FLOAT NULL;
ALTER TABLE application ADD COLUMN github_summary TEXT NULL;
ALTER TABLE application ADD COLUMN interview_questions TEXT NULL;
ALTER TABLE application ADD COLUMN interview_score FLOAT NULL;
