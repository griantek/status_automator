import os
import json
import time
import base64
import datetime
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import google.generativeai as genai
import re
from supabase import create_client, Client
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from fuzzywuzzy import fuzz  # For fuzzy matching

# Load environment variables
load_dotenv()

# Get sensitive data from environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# Supabase credentials from environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Encryption parameters from environment variables
ENCRYPTION_KEY = bytes.fromhex(os.getenv("ENCRYPTION_KEY"))
ENCRYPTION_IV = bytes.fromhex(os.getenv("ENCRYPTION_IV"))

# JSON files to store email data
LAST_EMAIL_FILE = "last_email.json"
EMAIL_LOG_FILE = "email_records.json"

def encrypt_text(text):
    """Encrypt text using AES-256-CBC."""
    if not text:
        return text
    text = str(text).encode('utf-8')
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(ENCRYPTION_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_text = text + b" " * (16 - len(text) % 16)  # Pad to 16-byte boundary
    encrypted = encryptor.update(padded_text) + encryptor.finalize()
    return encrypted.hex()

def extract_email_address(raw_email):
    """Extracts only the email address from the 'To' field."""
    match = re.search(r'[\w\.-]+@[\w\.-]+', raw_email)
    return match.group(0) if match else raw_email

def get_gmail_service():
    """Authenticate and return a Gmail API service instance."""
    creds = Credentials.from_authorized_user_file("token.json", ["https://www.googleapis.com/auth/gmail.readonly"])
    return build("gmail", "v1", credentials=creds)

def load_last_email():
    """Load the last saved email ID from file."""
    if os.path.exists(LAST_EMAIL_FILE):
        with open(LAST_EMAIL_FILE, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return None
    return None

def save_last_email(email_data):
    """Save the latest email details to JSON file."""
    with open(LAST_EMAIL_FILE, "w") as file:
        json.dump(email_data, file, indent=4)

def save_email_log(email_data):
    """Append new emails to email_records.json with full content and timestamps."""
    email_data["logged_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if os.path.exists(EMAIL_LOG_FILE):
        with open(EMAIL_LOG_FILE, "r") as file:
            try:
                email_log = json.load(file)
            except json.JSONDecodeError:
                email_log = []
    else:
        email_log = []
    email_log.append(email_data)
    with open(EMAIL_LOG_FILE, "w") as file:
        json.dump(email_log, file, indent=4)

def fetch_journal_data(to_email_only):
    """Fetch data from Supabase where username matches encrypted to_email_only."""
    encrypted_email = encrypt_text(to_email_only)
    response = supabase.table("journal_data").select("*").eq("username", encrypted_email).execute()
    return response.data

def clean_text(text):
    """Clean text for fuzzy matching: lowercase, remove special chars, normalize spaces."""
    if not text:
        return ""
    text = re.sub(r'[^\w\s]', '', text.lower())  # Remove special characters
    return ' '.join(text.split())  # Normalize spaces

def match_journal_details(email_info, journal_records):
    """Match journal_name and paper_title with fuzzy matching for journal_name."""
    email_journal = clean_text(email_info["journal_name"])
    email_manuscript = clean_text(email_info["manuscript_name"])
    best_match = None
    best_score = 0

    for record in journal_records:
        db_journal = clean_text(record.get("journal_name", ""))
        db_paper = clean_text(record.get("paper_title", ""))

        # Fuzzy match journal_name (ratio > 80 for similarity)
        journal_similarity = fuzz.ratio(email_journal, db_journal)

        # Check paper_title if it exists in DB
        paper_match = db_paper and fuzz.ratio(email_manuscript, db_paper) > 80

        if journal_similarity > 80:  # Threshold for a match
            if paper_match:
                # Perfect match: username, journal_name, and paper_title
                return record
            elif journal_similarity > best_score:
                # Partial match: username and journal_name only
                best_match = record
                best_score = journal_similarity

    return best_match  # Return best journal_name match if no paper_title match

def extract_email_content(message):
    """Extract email details and check if it's manuscript-status-related."""
    headers = message["payload"]["headers"]
    
    email_id = message.get("id", "Unknown ID")
    sender = next((header["value"] for header in headers if header["name"] == "From"), "Unknown")
    recipient = next((header["value"] for header in headers if header["name"] == "To"), "Unknown")
    subject = next((header["value"] for header in headers if header["name"] == "Subject"), "No Subject")
    timestamp = next((header["value"] for header in headers if header["name"] == "Date"), "Unknown Time")

    to_email_only = extract_email_address(recipient)

    forwarded_from = next((header["value"] for header in headers if header["name"] == "X-Forwarded-For"), None)
    return_path = next((header["value"] for header in headers if header["name"] == "Return-Path"), None)
    delivered_to = next((header["value"] for header in headers if header["name"] == "Delivered-To"), None)

    is_forwarded = forwarded_from or return_path or delivered_to

    body_data = ""
    if "data" in message["payload"]["body"]:
        body_data = message["payload"]["body"]["data"]
    elif "parts" in message["payload"]:
        for part in message["payload"]["parts"]:
            if part["mimeType"] == "text/plain":
                body_data = part["body"]["data"]
                break

    body = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="ignore") if body_data else "No Body"

    if not is_journal_related(body):
        return None

    journal_name, manuscript_name, status = extract_journal_details(body)
    if status is None:
        return None

    email_info = {
        "id": email_id,
        "sender": sender,
        "recipient": recipient,
        "to_email_only": to_email_only,
        "subject": subject,
        "body": body,
        "received_time": timestamp,
        "forwarded_from": forwarded_from,
        "return_path": return_path,
        "delivered_to": delivered_to,
        "is_forwarded": bool(is_forwarded),
        "journal_name": journal_name,
        "manuscript_name": manuscript_name,
        "status": status,
        "is_matched": False  # Default to unmatched
    }

    # Fetch and match journal data from Supabase
    journal_records = fetch_journal_data(to_email_only)
    if journal_records:
        print(f"📊 Found {len(journal_records)} potential matching records in database")
        matched_record = match_journal_details(email_info, journal_records)
        if matched_record:
            record_id = matched_record.get("id")
            print(f"🔍 Matched with record ID: {record_id}")
            
            email_info["is_matched"] = True
            email_info["db_journal_name"] = matched_record.get("journal_name")
            email_info["db_paper_title"] = matched_record.get("paper_title", "Not provided")
            email_info["match_status"] = "Full match" if matched_record.get("paper_title") else "Partial match (journal only)"
            email_info["record_id"] = record_id  # Store the record ID for reference
            
            # Update the journal status in the database
            if record_id:
                print(f"🔄 Updating status for record {record_id} to '{status}'")
                update_success = update_journal_status(record_id, status, email_id)
                email_info["status_updated_in_db"] = update_success
            else:
                print(f"⚠️ No record ID found in matched record!")
                email_info["status_updated_in_db"] = False
                
        else:
            print("❌ No match found among database records")
            email_info["match_status"] = "❌ No match found in DB"
    else:
        print(f"❌ No records found in database for email: {to_email_only}")
        email_info["match_status"] = "❌ No records found for this email"

    return email_info

def check_new_emails():
    """Fetch new emails and process only manuscript-status-related ones."""
    service = get_gmail_service()
    last_email_data = load_last_email()
    last_email_id = last_email_data.get("id") if last_email_data else None

    response = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=10).execute()
    messages = response.get("messages", [])

    if not messages:
        print("📭 No new emails.")
        return

    new_emails = []
    for msg in messages:
        msg_id = msg.get("id")
        if last_email_id and msg_id == last_email_id:
            break

        msg_data = service.users().messages().get(userId="me", id=msg_id).execute()
        email_info = extract_email_content(msg_data)

        if email_info is None:
            continue

        new_emails.append(email_info)

    new_emails.reverse()

    for email in new_emails:
        print("\n📩 **New Journal Email Received!** 📩")
        print(f"🔹 **From:** {email['sender']}")
        print(f"📨 **To:** {email['recipient']}")
        print(f"🔹 **Subject:** {email['subject']}")
        print(f"🔹 **Received Time:** {email['received_time']}")
        print(f"📜 **Manuscript Name:** {email['manuscript_name']}")
        print(f"📖 **Journal Name (Email):** {email['journal_name']}")
        
        # Display match status more prominently
        if email.get('is_matched', False):
            print(f"✅ **MATCHED WITH DATABASE RECORD** ✅")
            print(f"📋 **Record ID:** {email.get('record_id', 'Unknown')} (Use for manual verification)")
            print(f"📖 **Journal Name (DB):** {email.get('db_journal_name', 'Not matched')}")
            print(f"📜 **Paper Title (DB):** {email.get('db_paper_title', 'Not matched')}")
            
            # Display status update result
            if email.get('status_updated_in_db', False):
                print(f"✅ **DATABASE UPDATED** - Status set to: {email['status']}")
                print(f"🔍 **To check manually, view record ID: {email.get('record_id')}**")
            else:
                print(f"❓ **DATABASE NOT UPDATED** - Status change failed")
        else:
            print(f"❌ **NOT MATCHED** - No matching records in database")
        
        print(f"🔹 **Status:** {email['status']}")
        print(f"🔹 **Match Status:** {email['match_status']}")
        print("-" * 80)

        save_email_log(email)

    if new_emails:
        save_last_email(new_emails[-1])

def is_journal_related(email_body):
    """Check if an email is likely about a manuscript submission status."""
    email_body = email_body.lower()
    context_keywords = ["manuscript", "submission", "journal", "paper", "article"]
    intent_keywords = ["review", "editor", "decision", "status", "update", "received"]
    toc_indicators = ["table of contents", "toc alert", "new issue", "volume", "available online", "in this issue"]

    has_context = any(keyword in email_body for keyword in context_keywords)
    has_intent = any(keyword in email_body for keyword in intent_keywords)
    is_toc = any(indicator in email_body for indicator in toc_indicators)

    return has_context and has_intent and not is_toc

def extract_journal_details(email_body):
    """Use AI to extract journal name, manuscript name, and submission status."""
    if not is_journal_related(email_body):
        return None, None, None

    prompt = f"""
    Analyze the following email content and extract the **journal name**, **manuscript title**, and **submission status**. 
    The email MUST be a personalized notification about a manuscript submission process (e.g., 'Your manuscript has been accepted'), 
    and the status MUST reflect an outcome or update in that process (e.g., 'accepted', 'rejected', 'under review', 'revise and resubmit', etc.). 
    Exclude emails that are table of contents alerts, newsletters, or general journal updates (e.g., 'new issue available', 'full text PDF' are NOT valid statuses). 
    If the email isn’t about a specific manuscript submission status, return 'Unknown Status'.

    Email:
    {email_body}

    Respond in this exact format:
    Journal: [Journal Name]
    Manuscript: [Manuscript Title]
    Status: [Exact Status]
    
    If no journal is found, return 'Unknown Journal'.
    If no manuscript is detected, return 'Unknown Manuscript'.
    If the email is not about a manuscript submission status, return 'Unknown Status'.
    """

    try:
        model = genai.GenerativeModel("gemini-2.0-flash-lite")
        response = model.generate_content(prompt)
        extracted_text = response.text.strip()

        journal_match = re.search(r'Journal:\s*(.+)', extracted_text)
        manuscript_match = re.search(r'Manuscript:\s*(.+)', extracted_text)
        status_match = re.search(r'Status:\s*(.+)', extracted_text)

        journal_name = journal_match.group(1) if journal_match else "Unknown Journal"
        manuscript_name = manuscript_match.group(1) if manuscript_match else "Unknown Manuscript"
        status = status_match.group(1) if status_match else "Unknown Status"

        if "unknown status" in status.lower():
            return None, None, None

        return journal_name, manuscript_name, status

    except Exception as e:
        print(f"⚠️ Gemini API Error: {e}")
        return None, None, None

def update_journal_status(record_id, new_status, email_id):
    """Update the status field of a matched journal record in the database.
    
    Args:
        record_id: The ID of the journal record to update
        new_status: The new status to set
        email_id: The email ID that triggered this update (for reference)
    
    Returns:
        bool: True if update was successful, False otherwise
    """
    try:
        
        # Validate inputs before update
        if not record_id:
            print(f"❌ Invalid record ID: {record_id}")
            return False
            
        update_data = {
            "status": new_status,
            "updated_at": datetime.datetime.now().isoformat()  # Using the existing updated_at column
        }
        
        # More detailed error handling with response inspection
        try:
            response = supabase.table("journal_data").update(update_data).eq("id", record_id).execute()
            
            if not response.data:
                print(f"❌ No data returned from update operation for record ID: {record_id}")
                print(f"⚠️ This usually means the record doesn't exist or you don't have permission")
                return False
                
            if len(response.data) > 0:
                print(f"✅ Successfully updated journal record ID: {record_id} with status: {new_status}")
                return True
            else:
                print(f"❌ Failed to update journal record ID: {record_id} - No records affected")
                return False
                
        except Exception as api_error:
            print(f"❌ Supabase API error: {api_error}")
            return False
            
    except Exception as e:
        print(f"❌ Error updating journal status for record ID {record_id}: {e}")
        print(f"❓ Error type: {type(e).__name__}")
        return False

def monitor_email():
    """Continuously monitor the inbox every 10 seconds."""
    print("📡 Monitoring inbox for new emails...")
    while True:
        check_new_emails()
        time.sleep(10)

if __name__ == "__main__":
    monitor_email()