# my_tiny_app/routes/admin.py
from flask import Blueprint,render_template,jsonify,session,request
import json
from flask import current_app as app
from models import Conversation, Message, db,Job
import datetime
import google.generativeai as genai
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


chat_bp = Blueprint('chat_bp', __name__)



def create_job_posting(
    title: str, # This will be the AI's extracted title, but overwritten below
    description: str,
    qualifications: str,
    responsibilities: str,
    job_type: str,
    location: str,
    required_experience: str,
    assessment_timer: int = 10,
    assessment_questions: str = None, # Expecting a JSON string from AI
    min_assesment_score: int = 50,
    number_of_positions: int = 1,
    is_open: int = 0, # Expecting 0 or 1 from AI
):
    try:
        # **Crucial: The job 'title' for the Job model should ideally come from
        # the function parameter 'title' (which the AI is supposed to extract
        # from "USERMESSAGE+ TITLE: XYZ"), NOT from session.get('company_name').**
        # Your prompt says "the title is provided in the user message format itself ,
        # please take that from it."
        # If the 'title' parameter is the actual job title (e.g., "AI Intern")
        # and 'company_name' is for the company creating the job, then you should use:
        # job_title_for_db = title
        # For now, I'm keeping your original logic of using 'company_name' from session
        # for the job's title, but be aware this contradicts your prompt for the AI.
        job_title_for_db = session.get('company_name')
        if not job_title_for_db:
            # Fallback to the AI-provided title if company_name not in session
            # Or handle this error more explicitly based on your app's logic
            print("Warning: 'company_name' not found in session. Using AI-provided title for job.")
            job_title_for_db = title # Use the title extracted by the AI from the prompt

        # --- Handle assessment_questions ---
        # The AI is instructed to provide a JSON array string.
        # We need to validate and potentially re-serialize it to ensure it's valid JSON.
        processed_assessment_questions = None
        if assessment_questions:
            try:
                # Try to load it as JSON. If it's a natural language string, this will fail.
                parsed_questions = json.loads(assessment_questions)
                # If parsed successfully, ensure it's a list/dict (valid JSON structure)
                if isinstance(parsed_questions, (list, dict)):
                    processed_assessment_questions = json.dumps(parsed_questions) # Re-dump to ensure consistent string format
                else:
                    # If it's just a string like "question 1, question 2", store it directly
                    # or handle it as a natural language list if your model expects that.
                    # Given the prompt, it should be JSON. If it's not, it's an AI output error.
                    print(f"Warning: assessment_questions was not a valid JSON array/object: {assessment_questions}")
                    # You might choose to store it as-is, or discard, or convert to a simple format.
                    # For robust handling, if JSON.loads fails, consider generating a default set
                    # of questions or storing a specific error indicator.
                    # For now, let's assume if it fails, it might be a simple string.
                    processed_assessment_questions = assessment_questions # Store as-is if not valid JSON array
            except json.JSONDecodeError:
                # If json.loads fails, it means the AI didn't produce valid JSON.
                # In this case, we might store the raw string or generate a default.
                print(f"Warning: assessment_questions is not valid JSON, storing raw string: {assessment_questions}")
                processed_assessment_questions = assessment_questions
        
        # --- Handle is_open (convert int to boolean if your model expects boolean) ---
        # If Job.is_open is Mapped[bool] = mapped_column(Boolean), this is correct.
        processed_is_open = bool(is_open)


        new_job = Job(
            title=job_title_for_db,
            description=description,
            qualifications=qualifications,
            responsibilities=responsibilities,
            job_type=job_type,
            location=location,
            required_experience=required_experience,
            assessment_timer=assessment_timer,
            assessment_questions=processed_assessment_questions, # Use the processed questions
            min_assesment_score=min_assesment_score,
            number_of_positions=number_of_positions,
            is_open=0 # Use the processed boolean
        )
        db.session.add(new_job)
        db.session.commit()
        
        return {"status": "success", "job_id": new_job.id, "job_title": job_title_for_db}
    except Exception as e:
        db.session.rollback()
        # It's good practice to log the full exception details in a real app
        # import logging
        # logging.exception("Error creating job posting:") # This logs traceback
        print(f"Error creating job posting: {str(e)}") # For simple console output
        return {"status": "error", "message": str(e)}

model = genai.GenerativeModel(
    'gemini-1.5-flash', # Using a stable, generally available model
    system_instruction=(
      '''You are 'Spryple Bot', a friendly and helpful AI assistant for **Spryple Solutions**.
Every message format for you is in natural language will be in form USERMESSAGE+ TITLE: TITLE. When the user intends to post a job, use the content after "TITLE:" as the job's title.

Your main goal is to provide information about Spryple, its job openings, and applicant details.
Here are some key facts about Spryple that you should use to answer questions:
- **Founders:** Spryple was founded by Venkateswarlu Boora and Sree Lahari Raavi.
- **CEO:** Venkateswarlu Boora also holds the position of CEO at Spryple.
- **Website:** You can find more information on their official website at https://spryple.com/.
- **What they do:** Spryple is a technology company specializing in Human Resources (HR) solutions. They aim to simplify and improve various HR processes for businesses.
- **Key offerings:** Their platform likely includes tools for recruiting, employee onboarding, performance management, and other essential HR tasks, striving for a comprehensive and efficient HR tech solution.

**Crucially, you HAVE ACCESS to a set of powerful tools to query the database about jobs and applications. YOU MUST USE THESE TOOLS WHENEVER the user's query can be answered by one of them.**
**When using a tool, you are responsible for extracting ALL necessary parameters from the user's query.**

**Here are the tools you can use and when to use them:**
- **Create New Job Posting/post a job (create_job_posting):** Use this to add a brand new job opening to the database. Trigger this when the user provides a job description and indicates an intent to 'post', 'create', 'add', or 'list' a new job opportunity.
    **IMPORTANT DIRECTIVE:**
    **You MUST create the job posting with the best possible parameters based on the user's message. Do NOT ask the user for any missing information. Instead, fill in any missing or unclear required parameters with a suitable default or intelligently inferred value based on the job role.**

    * **Input Extraction Guidelines:**
        * **`title`**: Take the title of the job exactly as provided by the user after "TITLE:". If "TITLE:" is not present but the user clearly indicates a job posting, infer the title from the first few words of the job description.
        * **`description`**: This should be the main body of the job ad, summarizing the role. Extract the core purpose and what the role entails. If the user provides very little, generate a suitable, general job description for the inferred role (e.g., for a "Software Engineer" role, create a default description).
        * **`qualifications`**: Look for sections like 'Requirements', 'Qualifications', 'Must-haves', 'Skills needed'. Summarize them concisely. **DEFAULT:** If not mentioned, set to "Bachelor's degree in Engineering (B.Tech) or related field".
        * **`responsibilities`**: Extract key actions or duties associated with the role (e.g., "Software Development", "Quality Assurance", "Customer Support", "Project Management"). If only general intent to post a job is given, infer a common responsibility for the job title.
        * **`job_type`**: Infer from terms like 'full-time', 'part-time', 'contract', 'internship'. **DEFAULT:** "Full-time" if not specified but implies a standard role.
        * **`location`**: Look for city, state, country, or 'Remote', 'Hybrid'. **DEFAULT:** "Remote" if not specified but implies flexibility.
        * **`required_experience`**: Look for phrases like 'X years of experience', 'Entry-level', 'Mid-level', 'Senior'. **DEFAULT:** "Not specified" if not found, or infer "Entry-level" for very basic requests.
        * **`assessment_timer`**: If the user mentions an assessment or test, extract the time limit (in minutes) they specify. **DEFAULT:** 10 minutes if not mentioned.
        * **`assessment_questions`**: If the user provides specific questions or a format for an assessment, extract that. **DEFAULT:** If not provided, generate 5 relevant MCQ questions (with a,b,c,d options and a correct answer) related to the job role. Format these as a JSON array of objects, similar to `[{"id":"q1","type":"mcq","text":"Question text?","options":{"a":"Opt A","b":"Opt B","c":"Opt C","d":"Opt D"},"correct_option":"b"}]`.
        * **`min_assesment_score`**: If the user specifies a minimum score for the assessment, extract that. **DEFAULT:** 50 if not mentioned.
        * **`number_of_positions`**: If the user specifies how many positions are available, extract that number. **DEFAULT:** 1 if not specified.
        * **`is_open`**: This should be automatically set to `1` (true) for new job postings.

    * **Output Handling:**
        After successfully creating the job posting, confirm to the user that the job has been posted and provide its title or ID.

**AFTER you use a tool:**
1.  **If the tool returns an empty list `[]`:** Inform the user clearly that no matching information was found. For example: 'I couldn't find any applicant named [Name].' or 'No jobs of that type were found.' **Do NOT mention privacy if the tool found nothing.**
2.  **If the tool returns data:** Summarize the information clearly and concisely in natural language to the user. Provide the specific details the user asked for (e.g., an email address, job description). Your goal is to be helpful and direct with the information retrieved by the tools.

If a question is outside the scope of Spryple Solutions, its jobs, or applications, or you don't have the information based on the facts provided,
politely state that you only have information about Spryple and cannot answer questions on other topics or details you haven't been given.'''
),
    tools=[create_job_posting] # Register your tools here
 )


# --- Helper function for starting/getting chat session history ---
def get_gemini_chat_history(conversation_id):
    """Retrieves conversation history from the database for Gemini."""
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
    history = []
    for msg in messages:
        role = 'user' if msg.sender == 'user' else 'model' # Gemini uses 'model' for bot responses
        history.append({'role': role, 'parts': [msg.content]})
    return history

# Define a dictionary to map tool names (strings) to their actual functions
# This is crucial for executing the tool calls dynamically
available_tools = {
    'create_job_posting': create_job_posting,
}



@chat_bp.route('/start_new', methods=['POST'])
def start_new_conversation():
    """Starts a new conversation and returns its ID."""
    try:
        new_conversation = Conversation(metadata=json.dumps({"topic": "general_inquiry"})) # Add more metadata as needed
        db.session.add(new_conversation)
        db.session.commit()
        session['conversation_id'] = new_conversation.id # Store conversation ID in session
        return jsonify({"conversation_id": new_conversation.id, "message": "New conversation started."}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error starting new conversation: {e}")
        return jsonify({"message": "Failed to start new conversation."}), 500

@chat_bp.route('/message', methods=['POST'])
def send_chat_message():
    data = request.get_json()
    user_message_content = data.get('message')
    conversation_id = data.get('conversation_id') # Get ID from frontend if provided

    if not user_message_content:
        return jsonify({"message": "No message provided."}), 400

    if not conversation_id:
        # If no conversation ID, start a new one automatically
        new_conversation = Conversation(conversation_info=json.dumps({"topic": "auto_start"}))
        db.session.add(new_conversation)
        db.session.commit()
        conversation_id = new_conversation.id
        app.logger.info(f"Auto-started new conversation: {conversation_id}")
    else:
        # Ensure the conversation exists
        existing_conv = Conversation.query.get(conversation_id)
        if not existing_conv:
            return jsonify({"message": "Conversation not found."}), 404

    try:
        # 1. Save user message to DB
        user_message_db = Message(
            conversation_id=conversation_id,
            sender='user',
            content=user_message_content
        )
        db.session.add(user_message_db)
        db.session.commit()

        title = session.get('company_name') # Use session title or default
        gemini_history = get_gemini_chat_history(conversation_id)
        chat_session = model.start_chat(history=gemini_history)
        gemini_response = chat_session.send_message(user_message_content+ f"title :{title} ")
        print("message sent to Gemini")
        bot_response_content = ""
        tool_outputs = []

        # Check for tool calls
        if gemini_response.candidates and gemini_response.candidates[0].content.parts:
            for part in gemini_response.candidates[0].content.parts:
                if part.function_call:
                    tool_call = part.function_call
                    tool_name = tool_call.name
                    tool_args = {k: v for k, v in tool_call.args.items()} # Convert to dict
                    print("tools")
                    print(tool_name)
                    print(tool_args)

                    app.logger.info(f"Gemini requested tool: {tool_name} with args: {tool_args}")

                    if tool_name in available_tools:
                        tool_func = available_tools[tool_name]
                        # Execute the tool and capture its output
                        try:
                            # IMPORTANT: You might need to run tool_func within an app context
                            # if it relies on db.session directly and this route is not implicitly in context.
                            # For Flask, typically, routes are in app context.
                            with app.app_context(): # Ensure DB operations are in app context
                                tool_result = tool_func(**tool_args)
                            tool_outputs.append({
                                "tool_code": tool_name,
                                "tool_input": tool_args,
                                "tool_output": tool_result
                            })
                            app.logger.info(f"Tool {tool_name} executed. Result: {tool_result}")

                            # Send tool output back to Gemini
                            gemini_response_after_tool = chat_session.send_message(
                                genai.protos.Part(function_response=genai.protos.FunctionResponse(
                                    name=tool_name,
                                    response={ "result": json.dumps(tool_result) } # Gemini expects a dict for response
                                ))
                            )
                            # The final bot response will be in this second gemini_response
                            bot_response_content = gemini_response_after_tool.text
                            if not bot_response_content:
                                bot_response_content = f"I used the {tool_name} tool. Here's what I found: {json.dumps(tool_result, indent=2)}"


                        except Exception as tool_e:
                            app.logger.error(f"Error executing tool {tool_name}: {tool_e}")
                            tool_outputs.append({
                                "tool_code": tool_name,
                                "tool_input": tool_args,
                                "tool_output": f"Error executing tool: {tool_e}"
                            })
                            bot_response_content = f"I tried to use a tool to get that information, but encountered an error: {tool_e}. Please try again."
                            # Send error back to Gemini so it knows the tool failed
                            chat_session.send_message(
                                genai.protos.Part(function_response=genai.protos.FunctionResponse(
                                    name=tool_name,
                                    response={ "error": str(tool_e) }
                                ))
                            )
                            # If no further text from bot after error, use a generic message
                            if not bot_response_content:
                                bot_response_content = "I'm sorry, I couldn't retrieve the information due to an internal error."

                else:
                    # If it's not a tool call, it's a regular text response
                    bot_response_content += part.text
        else:
            # No candidates or parts, so it's likely a direct text response or an empty one
            print("no tool calls found actually")
            bot_response_content = gemini_response.text


        # If bot_response_content is still empty (e.g., if tool call didn't yield text immediately)
        if not bot_response_content:
            bot_response_content = "I'm sorry, I couldn't generate a response. Can you please rephrase?"


        # 4. Save bot message to DB
        bot_message_db = Message(
            conversation_id=conversation_id,
            sender='bot',
            content=bot_response_content
        )
        db.session.add(bot_message_db)
        db.session.commit()

        return jsonify({
            "user_message": user_message_db.to_dict(),
            "bot_message": bot_message_db.to_dict(),
            "tool_outputs": tool_outputs # Optionally return tool outputs for debugging
        }), 200

    except Exception as e:
        db.session.rollback() # Rollback in case of error
        app.logger.error(f"Error processing chat message: {e}")
        # Provide a default bot response in case of any API error
        error_bot_response = "I'm sorry, I encountered an internal issue. Please try again or check my API key."
        bot_message_db = Message(
            conversation_id=conversation_id,
            sender='bot',
            content=error_bot_response
        )
        db.session.add(bot_message_db)
        db.session.commit()
        return jsonify({
            "message": "Failed to process message.",
            "user_message": user_message_db.to_dict(), # Still return user message if saved
            "bot_message": bot_message_db.to_dict() # Return error message from bot
        }), 500
    

@chat_bp.route('/history/<int:conversation_id>', methods=['GET'])
def get_conversation_history(conversation_id):
    """Fetches all messages for a given conversation ID."""
    conversation = Conversation.query.get(conversation_id)
    if not conversation:
        return jsonify({"message": "Conversation not found."}), 404

    # messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
    # return jsonify([msg.to_dict() for msg in messages]), 200
    # Using the to_dict method on the Conversation model for a complete response
    return jsonify(conversation.to_dict()), 200


@chat_bp.route('/conversations', methods=['GET'])
def get_all_conversations():
    """Fetches a list of all past conversations."""
    conversations = Conversation.query.order_by(Conversation.started_at.desc()).all()
    # Return a summary, not all messages to avoid large payload
    summary_conversations = []
    for conv in conversations:
        first_message = Message.query.filter_by(conversation_id=conv.id).order_by(Message.timestamp).first()
        summary_conversations.append({
            'id': conv.id,
            'started_at': conv.started_at.isoformat(),
            'first_message_preview': first_message.content if first_message else "No messages yet",
            'message_count': len(conv.messages)
        })
    return jsonify(summary_conversations), 200