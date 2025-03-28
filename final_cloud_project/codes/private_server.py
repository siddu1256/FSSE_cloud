import hashlib
import json
import base64
import mysql.connector
from fuzzywuzzy import fuzz
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import socket

mysql_conn = mysql.connector.connect(
    host='localhost',
    user='username_of_DB',
    password='password_of_DB',
    database='FSSE_DB'
)
mysql_cursor = mysql_conn.cursor()


def fetch_aes_key_from_db(file_name):
    """Fetch AES key for a given file from the database."""
    mysql_cursor.execute("SELECT aes_key FROM document_metadata WHERE file_name = %s", (file_name,))
    result = mysql_cursor.fetchone()
    return result[0] if result else None  # Return AES key (Base64 encoded) if found


def hamming_distance(fp1, fp2):
    return sum(ch1 != ch2 for ch1, ch2 in zip(fp1, fp2))

def fetch_fingerprints_from_db():
    """Fetch all keyword fingerprints stored in the database."""
    mysql_cursor.execute("SELECT file_name, word, fingerprint FROM word_fingerprints")
    
    fingerprints = {}
    for file_name, keyword, keyword_fp in mysql_cursor.fetchall():
        if file_name not in fingerprints:
            fingerprints[file_name] = []
        fingerprints[file_name].append({'keyword': keyword, 'keyword_fp': keyword_fp})
    return fingerprints

def fuzzy_match(query_fp):
    """Find the closest matching keyword using Hamming distance."""
    keyword_index = fetch_fingerprints_from_db()
    
    if not keyword_index:
        return None

    hamlist = []
    for keywords in keyword_index.values():
        for entry in keywords:
            hamlist.append((hamming_distance(query_fp, entry['keyword_fp']), entry['keyword']))

    hamlist.sort(key=lambda x: x[0])  # Sort by lowest distance
    return hamlist[0][1] if hamlist else None  # Return closest match

def full_text_search(query_keyword,keyword_fp):
    closest_keyword = fuzzy_match(keyword_fp)  # Use Hamming distance

    if not closest_keyword:
        return {}  # No matches found

    keyword_index = fetch_fingerprints_from_db()
    matched_files = {}

    for file_name, keywords in keyword_index.items():
        for entry in keywords:
            if entry['keyword'] == closest_keyword:  # Match based on closest keyword
                if file_name not in matched_files:
                    matched_files[file_name] = []
                matched_files[file_name].append(entry['keyword'])  # Store matched keyword
    return matched_files

def decrypt_document(file_name, aes_key):
    """Decrypt a file using AES-GCM mode."""
    aes_key = aes_key + '=' * (4 - len(aes_key) % 4)  # Add padding if needed
    try:
        aes_key = base64.b64decode(aes_key)
    except ValueError as e:
        print(f"Error decoding AES key: {e}")
        return None

    try:
        with open(f"public_cloud/{file_name}.json", "r") as f:
            encrypted_data = json.load(f)

        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

def search_and_download(data):
    """Perform a secure search and download the top-matching documents."""
    
    # This will store the unique files to avoid duplicates
    sent_files = set()
    
    # This will store the final documents to send back to the client
    final_results = []

    # Process each keyword and its fingerprint in the input data
    for keyword, keyword_fp in data.items():
        # Full-text search for this keyword
        documents = full_text_search(keyword,keyword_fp)
        
        if not documents:
            print(f"No matching documents found for keyword: {keyword}.")
            continue
        
        # Rank documents using fuzzy matching
        ranked_results = []
        for file_name, _ in documents.items():
            aes_key_base64 = fetch_aes_key_from_db(file_name)

            if aes_key_base64 is None:
                print(f"No AES key found for {file_name}. Skipping this document.")
                continue

            plaintext = decrypt_document(file_name, aes_key_base64)
            
            if plaintext is None:
                print(f"Failed to decrypt {file_name}. Skipping this document.")
                continue

            # Calculate the fuzzy match score for the keyword
            score = fuzz.partial_ratio(keyword.lower(), plaintext.lower())

            ranked_results.append((file_name, plaintext, score))
        
        # Sort documents by relevance score (descending)
        ranked_results.sort(key=lambda x: x[2], reverse=True)

        # Select top 2 documents that haven't been sent yet
        for file_name, content, score in ranked_results[:2]:
            if file_name not in sent_files:
                sent_files.add(file_name)
                final_results.append((file_name, content, keyword, score))
    
    # If we have results, display them to the user
    if final_results:
        # Sort the final results by relevance score (highest first)
        final_results.sort(key=lambda x: x[3], reverse=True)
        
        # Show top results (we limit to top 2 from the entire set of results)
        for file_name, content, keyword, score in final_results[:2]:
            print(f"File: {file_name} | Matched Keyword: {keyword} | Relevance: {score}%")
            print(f"Preview: {content[:100]}...\n")
        return final_results
    else:
        print("0No relevant documents to send.")
        return None


def private_cloud_server():
    private_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    private_server_socket.bind(("localhost", 7000))  # Public Cloud Server
    private_server_socket.listen(5)
    print("Private Cloud is listening...")

    while True:
        public_server_conn, client_addr = private_server_socket.accept()
        data = json.loads(public_server_conn.recv(4096).decode())  # Receive data from public server
        print(data)
        # Perform the search and get the matching documents
        final_results = search_and_download(data)  # Perform fuzzy match on fingerprints
        print(final_results)
        # Prepare the response, include the file names and previews
        if final_results:
            matched_files = []
            for file_name, content, keyword, score in final_results:
                matched_files.append({
                    "file_name": file_name,
                    "matched_keyword": keyword,
                    "relevance_score": score,
                    "preview": content[:100]  # Send a preview of the content (first 100 chars)
                })
            print(matched_files)
            response = json.dumps({"matched_files": matched_files})
        else:
            response = json.dumps({"message": "No relevant documents found."})
        
       #send files back to client
        user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        user_socket.connect(("localhost", 5000))  # Public Cloud Server
        user_socket.send(json.dumps(response).encode())

if __name__ == "__main__":
    private_cloud_server()
