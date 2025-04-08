import socket
import json
import pyotp
import hashlib,base64
from cryptography.fernet import Fernet

#shared secret for TOTP (both user and server must have the same)
USER_SECRET = "JBSWY3DPEHPK3PXP"
USER_ID = "user123"
PASSWORD = "123456"

def generate_symmetric_key(secret):
    """Derive a 32-byte symmetric key from the OTP."""
    otp = pyotp.TOTP(secret).now()
    key = hashlib.sha256(otp.encode()).digest()  # Hash the OTP to get a 32-byte key for encrypting query purpose
    return base64.urlsafe_b64encode(key)


def encrypt_query(query, otp_key):
    """Encrypts the query using OTP as the key."""
    cipher = Fernet(otp_key)
    encrypted_query = cipher.encrypt(query.encode())
    return encrypted_query.decode()

def user_server(query):
    # Step 1: Generate OTP-based symmetric key
    otp_key = generate_symmetric_key(USER_SECRET)
    
    # Step 2: Encrypt query
    encrypted_query = encrypt_query(query, otp_key)
    
    # Step 3: Generate OTP Token for Authentication
    user_token = pyotp.TOTP(USER_SECRET).now()

    # Step 4: Prepare Message
    message = {
        "user_id": USER_ID,
        "password": PASSWORD,
        "user_token": user_token,
        "encrypted_query": encrypted_query
    }


    public_cloud_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    public_cloud_socket.connect(("localhost", 6001))#public cloud
    public_cloud_socket.send(json.dumps(message).encode())
    

    user_server_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    user_server_socket.bind(("localhost",5001))#user server for getting the documents metadata
    user_server_socket.listen(5)
    print("User server started....")

    while True:
        private_server_conn,private_server_addr=user_server_socket.accept()
        data=json.loads(private_server_conn.recv(4096).decode())
        print(data)

if __name__ == "__main__":
    query = input("Enter your search query: ")
    user_server(query)

"""
🔹 Step 1 - Semantic Expansion (Algorithm 2: SEA)
Input: A user types a keyword query QW = ["car"]

SEA expands it into synonyms:
RQW = ["car", "vehicle", "automobile", "sedan", ...]

🔹 Step 2 - Convert Query to Fingerprints
Use Algorithm 3 (KFPA) to convert each word in RQW into fingerprint vector Y_query.

Example:

plaintext
Copy
Edit
"car" → Y1 = [1, 0, 1, 0, ..., 0]
"vehicle" → Y2 = [1, 1, 0, 0, ..., 1]
...
These are semantic-aware binary representations.

🔹 Step 3 - Fuzzy Match (Algorithm 4: FYMA)
We want to find the closest matches for the query fingerprints in the keyword index.

The database already has keyword fingerprints (e.g., for "truck", "taxi", "bike", etc.)

We calculate Hamming Distance between each Y_query and the keyword fingerprint in the index FPI.

Hamming Distance (number of differing bits):

plaintext
Copy
Edit
H(Y_query, Y_index) = # of differing bits between them
If the distance is small enough, we consider it a fuzzy match.

The best match is selected as the most semantically relevant encrypted keyword.
"""
