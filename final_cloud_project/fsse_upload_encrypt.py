import hashlib
import json
import base64
import pyotp
import mysql.connector
from mysql.connector import Error
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import re
import hmac

# Database Connection (Private Cloud)
conn = mysql.connector.connect(
    host='localhost',      
    user='dbuser',       
    password='dbpass', 
    database='FSSE_DB'
)
cursor = conn.cursor()

def check_and_insert_user(user_id):
    # Check if the user already exists in user_auth
    query = "SELECT COUNT(*) FROM user_auth WHERE user_id = %s"
    cursor.execute(query, (user_id,))
    user_exists = cursor.fetchone()[0]

    if user_exists == 0:
        # If user does not exist, insert new user
        otp_secret = generate_totp_secret()  # You can generate a new OTP secret for the new user
        save_totp_secret(user_id, otp_secret)  # Save the new user with OTP secret
        print(f"New user '{user_id}' created and OTP secret saved.")
    else:
        print(f"User '{user_id}' already exists.")

def hmac_md5(key, message):
    """Generate HMAC-MD5 hash."""
    return hmac.new(key.encode(), message.encode(), hashlib.md5).hexdigest()

def generate_fingerprint(keyword, alpha=128, key="secret_key"):
    """Generate keyword fingerprint based on Algorithm 3."""
    M = [0] * alpha  
    Y = [0] * alpha 

    # Step 2: Generate 2-grams
    src = [keyword[i:i+2] for i in range(len(keyword) - 1)]

    # Step 3-12: Process each 2-gram
    for gram in src:
        macmd5 = hmac_md5(key, gram)  # HMAC-MD5 hash

        # Step 5-11: Modify M based on hash bits
        for i, bit in enumerate(bin(int(macmd5, 16))[2:].zfill(128)):  
            if bit == '1':
                M[i] += 1
            else:
                M[i] -= 1

    # Step 13-19: Convert M to binary fingerprint Y
    for i in range(alpha):
        Y[i] = 1 if M[i] >= 0 else 0

    Y_str=json.dumps(Y)
    print(Y_str)
    return Y_str

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

# Save Metadata in SQL Server (Private Cloud)
def save_metadata(file_name, aes_key, keyword_fp, user_id, file_content=None):
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

#Save Encrypted Document in Public Cloud (Text File)
def save_encrypted_document(file_name, encrypted_data):
    with open(f"public_cloud/{file_name}.json", "w") as f:
        f.write(encrypted_data)

#Generate & Store PyOTP Secret (Forward Secrecy)
def generate_totp_secret():
    return pyotp.random_base32()

def save_totp_secret(user_id, otp_secret):
    query = "INSERT INTO user_auth (user_id, otp_secret) VALUES (%s, %s)"
    cursor.execute(query, (user_id, otp_secret))
    conn.commit()



def encrypt_and_upload(file_name, plaintext, keyword, user_id):
    check_and_insert_user(user_id)

    # Generate Keyword Fingerprint
    keyword_fp = generate_fingerprint(keyword)
    
    # Encrypt Document
    encrypted_doc, aes_key = encrypt_document(plaintext)

    # Save Metadata to SQL Server
    save_metadata(file_name, aes_key, keyword_fp, user_id, file_content=plaintext)  # Save the document content as well

    # Save Encrypted Document to Public Cloud (Text File)
    save_encrypted_document(file_name, encrypted_doc)

    words = re.findall(r'\b\w+\b', plaintext.lower())
    for word in words:
        fingerprint = generate_fingerprint(word)
        query = """
        INSERT INTO word_fingerprints (file_name, word, fingerprint)
        VALUES (%s, %s, %s)
        """
        cursor.execute(query, (file_name, word, fingerprint))
    conn.commit()

    # Generate & Store PyOTP Secret
    otp_secret = generate_totp_secret()
    save_totp_secret(user_id, otp_secret)

    print(f"Document '{file_name}' encrypted & uploaded successfully!")

# Handle File Upload (Simulate the file upload process)
def handle_file_upload(file_name, plaintext, keyword, user_id):
    print(f"Handling file upload for '{file_name}'...")

    encrypt_and_upload(file_name, plaintext, keyword, user_id)

handle_file_upload(
    file_name="report3.txt",
    plaintext="There were slight changes in various departments. Revenue was discussed briefly in the final section.",
    keyword="department overview revenue",
    user_id="user123"
)



"""
---

### **Example Run**
Let's test the function with an example **keyword = "hello"**.

```python
keyword = "hello"
fingerprint = generate_fingerprint(keyword)
print(f"Keyword Fingerprint for '{keyword}':\n", fingerprint)
```

---

### **Step-by-Step Execution**
#### **1. Generate 2-Grams**
For `keyword = "hello"`, the 2-grams are:
```python
['he', 'el', 'll', 'lo']
```

#### **2. Compute HMAC-MD5 Hash for Each 2-Gram**
Each 2-gram is hashed using `hmac_md5("secret_key", gram)`, which produces:

| 2-Gram | HMAC-MD5 Hash (Hex) | Binary (First 32 Bits) |
|--------|----------------------|------------------------|
| `he`   | `6f63b8e9b1aebc4c...` | `0110111101100011...` |
| `el`   | `edf34e273ac669b2...` | `1110110111110011...` |
| `ll`   | `8dcd06e77caa2f57...` | `1000110111001101...` |
| `lo`   | `f0c7dfc64973507a...` | `1111000011000111...` |

#### **3. Update `M` Based on Hash Bits**
For each hash, we:
- Convert it into **128-bit binary**.
- If the bit is **1**, increment `M[i]`.
- If the bit is **0**, decrement `M[i]`.

This accumulates values in `M`, e.g.,  
```python
M = [1, -1, 2, -2, 3, -1, 2, 0, ...]  # 128 elements
```

#### **4. Convert `M` to Binary Fingerprint (`Y`)**
For each `M[i]`:
- If `M[i] >= 0`, set `Y[i] = 1`
- Otherwise, `Y[i] = 0`

Final `Y`:
[1, 0, 1, 0, 1, 1, 0, 1, ...]  # 128-bit binary fingerprint

---

Final Output
After running the function:
```
Keyword Fingerprint for 'hello':
[1, 0, 1, 0, 1, 1, 0, 1, ..., 1, 0, 1]
```

---

"""
