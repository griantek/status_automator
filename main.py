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
import requests  # Added for HTTP requests

# Load environment variables
load_dotenv()

# API key management
class APIKeyManager:
    def __init__(self):
        # Get API keys from environment variables
        self.api_keys = self._load_api_keys()
        self.current_key_index = 0
        self.config_file = "api_key_config.json"
        self._load_config()
        
        # Configure initial API key
        self._configure_current_key()
        
    def _load_api_keys(self):
        """Load API keys from environment variables."""
        keys = []
        i = 1
        # Try to get GEMINI_API_KEY (primary)
        primary_key = os.getenv("GEMINI_API_KEY")
        if primary_key:
            keys.append(primary_key)
            
        # Try to get GEMINI_API_KEY_1, GEMINI_API_KEY_2, etc.
        while True:
            key = os.getenv(f"GEMINI_API_KEY_{i}")
            if key:
                keys.append(key)
                i += 1
            else:
                break
                
        if not keys:
            raise ValueError("No Gemini API keys found in environment variables")
            
        print(f"🔑 Loaded {len(keys)} Gemini API key(s)")
        return keys
        
    def _load_config(self):
        """Load the last used API key index from config file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.current_key_index = config.get('current_key_index', 0)
                    
                    # Make sure the index is valid (in case fewer keys are available now)
                    if self.current_key_index >= len(self.api_keys):
                        self.current_key_index = 0
                        
                    print(f"📄 Loaded API key configuration, using key #{self.current_key_index+1}")
            except Exception as e:
                print(f"⚠️ Error loading API key configuration: {e}")
                self.current_key_index = 0
    
    def _save_config(self):
        """Save the current key index to the config file."""
        config = {'current_key_index': self.current_key_index}
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
            
    def _configure_current_key(self):
        """Configure Gemini with the current API key."""
        if 0 <= self.current_key_index < len(self.api_keys):
            genai.configure(api_key=self.api_keys[self.current_key_index])
            print(f"🔄 Using Gemini API key #{self.current_key_index+1}")
            return True
        return False
    
    def get_current_key(self):
        """Return the currently active API key."""
        return self.api_keys[self.current_key_index]
        
    def rotate_key(self):
        """Switch to the next available API key."""
        previous_key = self.current_key_index
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        
        if self._configure_current_key():
            self._save_config()
            print(f"🔄 Rotated from API key #{previous_key+1} to #{self.current_key_index+1}")
            return True
        return False
        
    def handle_api_error(self, error):
        """Handle different Gemini API errors with appropriate strategies.
        
        HTTP Status Codes:
        - 400: INVALID_ARGUMENT/FAILED_PRECONDITION - Bad request formatting or free tier limitations
        - 403: PERMISSION_DENIED - API key permissions issue
        - 404: NOT_FOUND - Resource not found
        - 429: RESOURCE_EXHAUSTED - Rate limit/quota exceeded
        - 500: INTERNAL - Server error (might be due to long context)
        - 503: UNAVAILABLE - Service temporarily overloaded
        - 504: DEADLINE_EXCEEDED - Request timeout
        """
        error_str = str(error).lower()
        error_code = None
        
        # Try to extract HTTP error code if available
        for code in ["400", "403", "404", "429", "500", "503", "504"]:
            if code in error_str:
                error_code = int(code)
                break
        
        # Check for specific error conditions
        quota_exceeded = any(msg in error_str for msg in [
            "quota exceeded", 
            "resource exhausted",
            "rate limit",
            "too many requests",
            "429"
        ])
        
        timeout_error = any(msg in error_str for msg in [
            "deadline exceeded",
            "timeout",
            "timed out",
            "504"
        ])
        
        server_error = any(msg in error_str for msg in [
            "internal",
            "unavailable",
            "server error",
            "500",
            "503"
        ])
        
        permission_error = any(msg in error_str for msg in [
            "permission denied",
            "unauthorized",
            "403"
        ])
        
        invalid_request = any(msg in error_str for msg in [
            "invalid argument",
            "bad request",
            "400",
            "failed precondition"
        ])
        
        # Handle based on error type
        if quota_exceeded or error_code == 429:
            print(f"⚠️ API quota/rate limit exceeded for key #{self.current_key_index+1}. Rotating to next key.")
            return self.rotate_key()
            
        elif timeout_error or error_code == 504:
            print(f"⚠️ API request timeout for key #{self.current_key_index+1}. Could be due to large input/context.")
            # Timeout often indicates the request is too complex, try next key
            return self.rotate_key()
            
        elif server_error or error_code in [500, 503]:
            print(f"⚠️ Gemini API server error. The service might be temporarily overloaded.")
            # For server errors, let's rotate keys as the next server might respond
            return self.rotate_key()
            
        elif permission_error or error_code == 403:
            print(f"❌ API key #{self.current_key_index+1} permission denied. Key may be invalid or revoked.")
            # Definitely rotate for permission errors - key is invalid
            return self.rotate_key()
            
        elif invalid_request or error_code == 400:
            # For 400 errors, the request format is the issue, not the key
            if "free tier" in error_str or "billing" in error_str:
                print(f"❌ Free tier not available in your region for key #{self.current_key_index+1}. Rotating.")
                return self.rotate_key()
            else:
                print(f"❌ Invalid request format: {error}")
                # Don't rotate for formatting errors as they'll likely happen with any key
                return False
                
        elif error_code == 404:
            print(f"❌ Resource not found: {error}")
            # Don't rotate for 404s as they're specific to the request, not the key
            return False
            
        else:
            print(f"❌ Unhandled API error: {error}")
            # For unknown errors, let's try rotation as a fallback strategy
            return self.rotate_key()

# Initialize the API key manager
api_key_manager = APIKeyManager()

# Get sensitive data from environment variables
GEMINI_API_KEY = api_key_manager.get_current_key()  # Initial key setup

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

    # Truncate email body if it's too long to avoid timeout errors
    max_length = 8000
    truncated_body = email_body[:max_length] if len(email_body) > max_length else email_body
    if len(email_body) > max_length:
        truncated_body += "\n[Email truncated due to length]"

    prompt = f"""
    Analyze the following email content and extract the **journal name**, **manuscript title**, and **submission status**. 
    The email MUST be a personalized notification about a manuscript submission process (e.g., 'Your manuscript has been accepted'), 
    and the status MUST reflect an outcome or update in that process (e.g., 'accepted', 'rejected', 'under review', 'revise and resubmit', etc.). 
    Exclude emails that are table of contents alerts, newsletters, or general journal updates (e.g., 'new issue available', 'full text PDF' are NOT valid statuses). 
    If the email isn't about a specific manuscript submission status, return 'Unknown Status'.

    Email:
    {truncated_body}

    Respond in this exact format:
    Journal: [Journal Name]
    Manuscript: [Manuscript Title]
    Status: [Exact Status]
    
    If no journal is found, return 'Unknown Journal'.
    If no manuscript is detected, return 'Unknown Manuscript'.
    If the email is not about a manuscript submission status, return 'Unknown Status'.
    """

    max_retries = len(api_key_manager.api_keys) * 2  # Allow multiple tries per key
    retries = 0
    
    while retries < max_retries:
        try:
            # Configure model with safety settings and parameters to avoid issues
            model = genai.GenerativeModel(
                model_name="gemini-2.0-flash-lite",
                generation_config={
                    "temperature": 0.1,            # Lower temperature for more consistent output
                    "max_output_tokens": 200,      # Limit output size
                    "top_p": 0.95,                 # More focused sampling
                    "top_k": 40                    # More focused token selection
                },
                safety_settings=[
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_ONLY_HIGH"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_ONLY_HIGH"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"}
                ]
            )
            
            # Set request timeout
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
            
            # Try to rotate to next key if applicable error
            if api_key_manager.handle_api_error(e):
                retries += 1
                print(f"🔁 Retry attempt {retries}/{max_retries} with new API key")
            else:
                # For errors that don't trigger rotation, implement exponential backoff
                wait_time = min(30, 2 ** (retries % 5))  # Cap at 30 seconds
                print(f"⏱️ Error doesn't require key rotation. Waiting {wait_time} seconds before retry...")
                time.sleep(wait_time)  # Exponential backoff with cap
                retries += 1
                
            if retries >= max_retries:
                print("❌ Maximum retry attempts reached. Cannot extract journal details.")
                break
    
    return None, None, None

def update_journal_status(record_id, new_status, email_id):
    """Update the status field of a matched journal record by calling the status bot service.
    
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
        
        external_service_success = False
        
        # Get the status bot URL from environment variables
        status_bot_url = os.getenv("JSTATUSBOT_URL")
        if status_bot_url:
            # Make request to the status bot service
            try:
                print(f"🔄 Calling status bot service for record ID: {record_id}")
                response = requests.post(
                    f"{status_bot_url}/upload-status",
                    headers={"Content-Type": "application/json"},
                    json={"journalId": record_id}
                )
                
                # Check if the request was successful
                if response.ok:
                    data = response.json()
                    if data.get("status") == "success":
                        print(f"✅ Status bot service processed the request successfully")
                        external_service_success = True
                    else:
                        print(f"⚠️ Status bot service returned failure: {data.get('message', 'Unknown error')}")
                else:
                    print(f"⚠️ Status bot service returned error: {response.status_code} - {response.text}")
            
            except Exception as e:
                print(f"⚠️ Error calling status bot service: {e}")
                # Continue to database update regardless of external service error
        else:
            print("⚠️ JSTATUSBOT_URL environment variable not set, skipping external service call")
        
        # Always update the Supabase database, regardless of external service result
        update_data = {
            "status": new_status,
            "updated_at": datetime.datetime.now().isoformat()
        }
        
        print(f"🔄 Updating status in database to '{new_status}' for record ID: {record_id}")
        update_response = supabase.table("journal_data").update(update_data).eq("id", record_id).execute()
        
        if not update_response.data:
            print(f"⚠️ Supabase update returned no data for record ID: {record_id}")
            return external_service_success  # Return external service status if database update ambiguous
            
        print(f"✅ Successfully updated journal record ID: {record_id} with status: {new_status}")
        return True  # Database was updated successfully
            
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