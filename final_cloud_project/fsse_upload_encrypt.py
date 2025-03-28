import hashlib
import json
import base64
import pyotp
import mysql.connector
from mysql.connector import Error
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import re

# Database Connection (Private Cloud)
conn = mysql.connector.connect(
    host='localhost',       # Your MySQL host, usually 'localhost'
    user='username_of_DB',
    password='password_of_DB',
    database='FSSE_DB'
)
cursor = conn.cursor()

def check_and_insert_user(user_id):
    # Check if the user already exists in user_auth
    query = "SELECT COUNT(*) FROM user_auth WHERE user_id = %0s"
    cursor.execute(query, (user_id,))
    user_exists = cursor.fetchone()[0]

    if user_exists == 0:
        # If user does not exist, insert new user
        otp_secret = generate_totp_secret()  # You can generate a new OTP secret for the new user
        save_totp_secret(user_id, otp_secret)  # Save the new user with OTP secret
        print(f"New user '{user_id}' created and OTP secret saved.")
    else:
        print(f"User '{user_id}' already exists.")

# 📌 Step 1: Generate Keyword Fingerprint
def generate_keyword_fingerprint(keyword):
    return hashlib.sha256(keyword.encode()).hexdigest()

# 📌 Step 2: AES Encryption for Document
def encrypt_document(plaintext):
    key = get_random_bytes(16)  # 128-bit AES key
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    encrypted_data = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

    return json.dumps(encrypted_data), base64.b64encode(key).decode()

# 📌 Step 3: Save Metadata in SQL Server (Private Cloud)
def save_metadata(file_name, aes_key, keyword_fp, user_id, file_content=None):
    # Insert into document_metadata table
    query = """
    INSERT INTO document_metadata (file_name, aes_key, keyword_fp, user_id, file_content)
    VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (file_name, aes_key, keyword_fp, user_id, file_content))
    conn.commit()

    # Insert into user_documents table (Track user uploads)
    query = """
    INSERT INTO user_documents (user_id, file_name)
    VALUES (%s, %s)
    """
    cursor.execute(query, (user_id, file_name))
    conn.commit()

# 📌 Step 4: Save Encrypted Document in Public Cloud (Text File)
def save_encrypted_document(file_name, encrypted_data):
    with open(f"public_cloud/{file_name}.json", "w") as f:
        f.write(encrypted_data)

# 📌 Step 5: Generate & Store PyOTP Secret (Forward Secrecy)
def generate_totp_secret():
    return pyotp.random_base32()

def save_totp_secret(user_id, otp_secret):
    query = "INSERT INTO user_auth (user_id, otp_secret) VALUES (%s, %s)"
    cursor.execute(query, (user_id, otp_secret))
    conn.commit()

# 📌 Step 6: Extract Words and Hash Them
def extract_and_hash_words(plaintext):
    # Extract words by splitting text and removing non-alphanumeric characters
    words = re.findall(r'\b\w+\b', plaintext.lower())
    word_hashes = {word: hashlib.sha256(word.encode()).hexdigest() for word in words}
    return word_hashes

# 📌 Step 7: Store Word Fingerprints in Database
def store_word_fingerprints(file_name, word_hashes):
    for word, fingerprint in word_hashes.items():
        query = """
        INSERT INTO word_fingerprints (file_name, word, fingerprint)
        VALUES (%s, %s, %s)
        """
        cursor.execute(query, (file_name, word, fingerprint))
    conn.commit()

# 📌 Step 8: Run Full Workflow
def encrypt_and_upload(file_name, plaintext, keyword, user_id):
    check_and_insert_user(user_id)

    # Generate Keyword Fingerprint
    keyword_fp = generate_keyword_fingerprint(keyword)
    
    # Encrypt Document
    encrypted_doc, aes_key = encrypt_document(plaintext)

    # Save Metadata to SQL Server
    save_metadata(file_name, aes_key, keyword_fp, user_id, file_content=plaintext)  # Save the document content as well

    # Save Encrypted Document to Public Cloud (Text File)
    save_encrypted_document(file_name, encrypted_doc)

    # Extract and Hash Words, then Store in Database
    word_hashes = extract_and_hash_words(plaintext)
    store_word_fingerprints(file_name, word_hashes)

    # Generate & Store PyOTP Secret
    otp_secret = generate_totp_secret()
    save_totp_secret(user_id, otp_secret)

    print(f"Document '{file_name}' encrypted & uploaded successfully!")

# 📌 Step 9: Handle File Upload (Simulate the file upload process)
def handle_file_upload(file_name, plaintext, keyword, user_id):
    print(f"0Handling file upload for '{file_name}'...")

    # Simulate the file upload process
    encrypt_and_upload(file_name, plaintext, keyword, user_id)

# 📌 Example Usage
handle_file_upload(
    file_name="finance_report.txt",
    plaintext="The company's revenue increased by 20% this quarter.",
    keyword="company revenue",
    user_id="user123"
)
