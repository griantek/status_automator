# Journal Status Email Automator

This application automatically monitors a Gmail inbox for journal submission status emails, extracts key information using AI, and updates matching records in a Supabase database.

## Features

- 📨 Automatically monitor Gmail inbox for new journal submission status emails
- 🔍 Extract journal name, manuscript title, and submission status using Google's Gemini AI
- 🔄 Match emails to existing journal submissions in Supabase database
- ✅ Automatically update submission status in database
- 🔒 Securely handle sensitive information with encryption

## 🚀 Setup Guide

### Prerequisites

- A Linux-based system (Ubuntu/Debian recommended)
- Python 3.8+ 
- Gmail account with API access enabled
- Supabase account and project
- Google Gemini API key

### Step 1: Clone the Repository

```bash
git clone <repository-url> journal-status-automator
cd journal-status-automator
```

### Step 2: Create Environment Variables

Create a `.env` file with the following variables:

```
GEMINI_API_KEY=your_gemini_api_key_here
SUPABASE_URL=your_supabase_url_here
SUPABASE_KEY=your_supabase_key_here
ENCRYPTION_KEY=32_byte_hex_encryption_key
ENCRYPTION_IV=16_byte_hex_initialization_vector
```

To generate encryption keys:

```python
import os
import binascii

# Generate a random 32-byte key for AES-256
key = os.urandom(32)
print(f"ENCRYPTION_KEY={binascii.hexlify(key).decode()}")

# Generate a random 16-byte initialization vector
iv = os.urandom(16)
print(f"ENCRYPTION_IV={binascii.hexlify(iv).decode()}")
```

### Step 3: Set Up Gmail API Authentication

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the Gmail API
4. Create OAuth 2.0 credentials
5. Download the credentials as `credentials.json`
6. Generate token.json by running the authentication script:

```bash
python gmail_auth.py  # This script should be created separately
```

### Step 4: Create Virtual Environment and Install Dependencies

Make the setup script executable:

```bash
chmod +x setup_venv.sh
```

Run the setup script:

```bash
./setup_venv.sh
```

This will:
- Install required system packages
- Create a Python virtual environment
- Install all dependencies from requirements.txt

### Step 5: Configure Supabase Database

Your Supabase database should have a `journal_data` table with at least these fields:
- `id` (primary key)
- `username` (encrypted email address)
- `journal_name` (name of the journal)
- `paper_title` (title of the manuscript)
- `status` (current status of the submission)
- `updated_at` (timestamp of the last update)

### Step 6: Run the Application

Make the run script executable:

```bash
chmod +x run.sh
```

Start monitoring emails:

```bash
./run.sh
```

Or manually activate the environment and run:

```bash
source venv/bin/activate
python main.py
```

## How It Works

1. **Gmail Monitoring**: The app checks for new emails in the Gmail inbox every 10 seconds.

2. **Email Processing**:
   - Extracts sender, recipient, subject, and body
   - Determines if the email is related to a journal submission status
   - Uses AI to extract journal name, manuscript name, and status

3. **Database Matching**:
   - Looks up the recipient email in the Supabase database
   - Uses fuzzy matching for journal names and paper titles
   - Identifies the correct submission record to update

4. **Status Update**:
   - Updates the submission status in the database
   - Saves a log of processed emails

5. **Security**:
   - All emails in the database are stored encrypted
   - Sensitive information is stored in environment variables

## Logs and Monitoring

- `last_email.json`: Stores information about the last processed email
- `email_records.json`: Contains a log of all processed emails

## Troubleshooting

### Common Issues

1. **Authentication errors with Gmail API**:
   - Check that your `token.json` file is valid and not expired
   - Run the authentication script again to refresh the token

2. **Database connection issues**:
   - Verify Supabase URL and key in the `.env` file
   - Check network connection to Supabase

3. **Email matching problems**:
   - Ensure that email addresses in your database are correctly encrypted
   - Check for potential fuzzy matching issues with similar journal names

### Debugging

To enable more detailed logs, you can modify the print statements in the code to output additional information.

## License

[Your License Information]

## Contributors

[Your Contributors Information]
