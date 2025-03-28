import socket
import json
from textblob import Word
import hashlib
import pyotp

def verify_time_based_otp(secret, token):
    return pyotp.TOTP(secret).verify(token)

def generate_fingerprint(query):
    result={}
    for i in query:
        result[i]=hashlib.sha256(i.encode()).hexdigest()
    return result

# Mock keyword dictionary (replace with your method to get closest match)
keyword_dictionary = {"bank": "bank", "loan": "loan", "credit": "credit", "finance": "finance"}

def find_closest_keyword(query):
    """Find the closest keyword from the predefined dictionary (not fuzzy search)."""
    return keyword_dictionary.get(query.lower(), query)  # Return original if no match

def semantic_expansion(keyword):
    """Expand keyword using synonyms."""
    word = Word(keyword)
    synonyms = word.synsets
    expanded_words = [keyword]  # Always keep original word

    for synset in synonyms:
        for lemma in synset.lemmas():
            synonym = lemma.name().replace('_', ' ')
            if synonym.lower() != keyword.lower():  # Avoid duplicates
                expanded_words.append(synonym)

    return list(set(expanded_words))  # Remove duplicates

def public_cloud_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 6000))  # Public Cloud Server
    server_socket.listen(5)
    print("Public Cloud is listening...")

    while True:
        conn, addr = server_socket.accept()

        #receives data with keyword
        data = json.loads(conn.recv(4096).decode())
        query = data["data"]
        user_totp_secret=data["user_totp_secret"]
        user_token=data["user_token"]
        if not verify_time_based_otp(user_totp_secret, user_token):
            print("❌ Authentication Failed! Invalid or expired OTP.")
            return
        else:
            print("successfully authenticated")
            closest_keyword = find_closest_keyword(query)  # Step 1: Find closest keyword
            print("closest_keywords:",closest_keyword)
            expanded_keywords = semantic_expansion(closest_keyword)  # Step 2: Semantic Expansion
            print("expanded_keywords",expanded_keywords)
            keyword_fingerprint_dict = generate_fingerprint(expanded_keywords)  # Step 4: Generate Fingerprints
            # Send to Private Cloud
            
            private_cloud_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            private_cloud_socket.connect(("localhost", 7000))  # Private Cloud Server
            private_cloud_socket.send(json.dumps(keyword_fingerprint_dict).encode())
            private_cloud_socket.close()
            conn.close()

if __name__ == "__main__":
    public_cloud_server()
