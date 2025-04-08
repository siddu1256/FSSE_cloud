import json
import base64
import mysql.connector
from fuzzywuzzy import fuzz
from Crypto.Cipher import AES
import socket

mysql_conn = mysql.connector.connect(
    host='localhost',
    user='dbuser',
    password='dbpass',
    database='FSSE_DB'
)
mysql_cursor = mysql_conn.cursor()


def fetch_aes_key_from_db(file_name):
    """Fetch AES key for a given file from the database."""
    mysql_cursor.execute("SELECT aes_key FROM document_metadata WHERE file_name = %s", (file_name,))
    result = mysql_cursor.fetchone()
    return result[0] if result else None


def fetch_fingerprints_from_db():
    """Fetch all word fingerprints from DB and organize by file."""
    mysql_cursor.execute("SELECT file_name, word, fingerprint FROM word_fingerprints")
    file_dict = {}
    for file_name, keyword, keyword_fp in mysql_cursor.fetchall():
        if file_name not in file_dict:
            file_dict[file_name] = []
        file_dict[file_name].append({
            'keyword': keyword,
            'keyword_fp': keyword_fp
        })
    return file_dict


def hamming_distance(str1, str2):
    """Return Hamming Distance between two equal-length strings"""
    if len(str1) != len(str2):
        return float('inf')
    return sum(c1 != c2 for c1, c2 in zip(str1, str2))


def fuzzy_match(query_fp, keyword_index):
    """Find the closest keyword using Hamming distance."""
    hamlist = []
    for keywords in keyword_index.values():
        for entry in keywords:
            hamlist.append((hamming_distance(query_fp, entry['keyword_fp']), entry['keyword']))
    hamlist.sort(key=lambda x: x[0])
    return hamlist[0][1] if hamlist else None


def full_text_search(query_keyword, keyword_fp):
    keyword_index = fetch_fingerprints_from_db()
    closest_keyword = fuzzy_match(keyword_fp, keyword_index)

    if not closest_keyword:
        return {}

    matched_files = {}
    for file_name, keywords in keyword_index.items():
        for entry in keywords:
            if entry['keyword'] == closest_keyword:
                if file_name not in matched_files:
                    matched_files[file_name] = []
                matched_files[file_name].append(entry['keyword'])
    return matched_files


def decrypt_document(file_name, aes_key):
    """Decrypt a file using AES-GCM."""
    aes_key = aes_key + '=' * (4 - len(aes_key) % 4)
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
        print(f"Error during decryption of {file_name}: {e}")
        return None



def search_and_download(data):
    sent_files = set()
    final_results = []
    threshold=50

    for keyword, keyword_fp in data.items():
        documents = full_text_search(keyword, keyword_fp)

        if not documents:
            print(f"No matching documents found for keyword: {keyword}")
            continue

        ranked_results = []

        for file_name in documents:
            if file_name in sent_files:
                continue

            aes_key_base64 = fetch_aes_key_from_db(file_name)
            if not aes_key_base64:
                print(f"No AES key found for file: {file_name}")
                continue

            plaintext = decrypt_document(file_name, aes_key_base64)
            if not plaintext:
                print(f"Decryption failed or empty content for file: {file_name}")
                continue

            score = fuzz.partial_ratio(keyword.lower(), plaintext.lower())
            if score>=threshold:
                ranked_results.append((file_name, plaintext, keyword, score))

        ranked_results.sort(key=lambda x: x[3], reverse=True)

        for result in ranked_results[:2]:
            file_name = result[0]
            if file_name not in sent_files:
                sent_files.add(file_name)
                final_results.append(result)

    if final_results:
        final_results.sort(key=lambda x: x[3], reverse=True)
        print("\nTop Matched Documents:")
        for file_name, content, keyword, score in final_results[:2]:
            print(f"File: {file_name} | Matched Keyword: {keyword} | Relevance: {score}%")
            print(f"Preview: {content[:100]}...\n")
        return final_results
    else:
        print("No relevant documents to send.")
        return []


def private_cloud_server():
    private_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    private_server_socket.bind(("localhost", 7001))
    private_server_socket.listen(5)
    print("Private Cloud is listening...")

    while True:
        public_server_conn, client_addr = private_server_socket.accept()
        data = json.loads(public_server_conn.recv(4096).decode())
        print("Received from Public Cloud:", data)

        final_results = search_and_download(data)

        if final_results:
            matched_files = []
            for file_name, content, keyword, score in final_results:
                matched_files.append({
                    "file_name": file_name,
                    "matched_keyword": keyword,
                    "relevance_score": score,
                    "preview": content[:100]
                })
            response = json.dumps({"matched_files": matched_files})
        else:
            response = json.dumps({"message": "No relevant documents found."})

        user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        user_socket.connect(("localhost", 5001))
        user_socket.send(response.encode())
        user_socket.close()


if __name__ == "__main__":
    private_cloud_server()
