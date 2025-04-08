import socket
import json
from textblob import Word
import hashlib
import pyotp
import hashlib,base64
import hmac
from cryptography.fernet import Fernet

# Simulated user database
user_db = {
    "user123": "JBSWY3DPEHPK3PXP"
}

def verify_time_based_otp(user_id, token):
    """Verifies OTP using the pre-shared secret."""
    if user_id not in user_db:
        return False
    secret = user_db[user_id]
    return pyotp.TOTP(secret).verify(token)

def generate_symmetric_key(secret):
    """Derives a 32-byte symmetric key from the OTP for decryption."""
    otp = pyotp.TOTP(secret).now()
    key = hashlib.sha256(otp.encode()).digest()  # Hash OTP to 32-byte key for decrypting the query
    return base64.urlsafe_b64encode(key)

def decrypt_query(encrypted_query, otp_key):
    """Decrypts the encrypted query using OTP key."""
    cipher = Fernet(otp_key)
    print("decrypt query: ",cipher.decrypt(encrypted_query.encode()).decode())
    return cipher.decrypt(encrypted_query.encode()).decode()


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

    print(Y)
    return Y

#semantic expansion to find related words
keyword_dictionary = {"bank": "bank", "loan": "loan", "credit": "credit", "finance": "finance"}

def find_closest_keyword(query): #find the related words
    """Find the closest keyword from the predefined dictionary (not fuzzy search)."""
    return keyword_dictionary.get(query.lower(), query)

#step-3: semantic expansion based on textblob
def semantic_expansion(keyword):
    """Expand keyword using synonyms."""
    word = Word(keyword)
    synonyms = word.synsets
    expanded_words = [keyword]

    for synset in synonyms:
        for lemma in synset.lemmas():
            synonym = lemma.name().replace('_', ' ')
            if synonym.lower() != keyword.lower():
                expanded_words.append(synonym)

    return list(set(expanded_words))

def public_cloud_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 6001)) # public server
    server_socket.listen(5)
    print("Public Cloud is listening...")

    while True:
        conn, addr = server_socket.accept()
        data = json.loads(conn.recv(4096).decode())

        user_id = data["user_id"]
        user_token = data["user_token"]
        encrypted_query = data["encrypted_query"]

        # Step 1: Verify user using OTP
        if not verify_time_based_otp(user_id, user_token):
            print("Authentication Failed! Invalid or expired OTP.")
            conn.close()
            continue

        print("Successfully authenticated user:", user_id)

        #Generate symmetric key for decryption using pyotp token
        otp_key = generate_symmetric_key(user_db[user_id])

        # Step 3: Decrypt the query
        try:
            decrypted_query = decrypt_query(encrypted_query, otp_key)
            print("Decrypted Query:", decrypted_query)
        except Exception as e:
            print("Decryption Failed:", str(e))
            conn.close()
            continue

        closest_keyword = find_closest_keyword(decrypted_query)
        expanded_keywords = semantic_expansion(closest_keyword)
        keyword_fingerprint_dict={}
        for i in expanded_keywords:
            keyword_fingerprint_dict[i]=generate_fingerprint(i)
        print(keyword_fingerprint_dict)
        private_cloud_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        private_cloud_socket.connect(("localhost", 7001))  # Private Cloud Server
        private_cloud_socket.send(json.dumps(keyword_fingerprint_dict).encode())
        private_cloud_socket.close()
        conn.close()

if __name__ == "__main__":
    public_cloud_server()
