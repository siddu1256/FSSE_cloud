# FSSE - Fuzzy Semantic Searchable Encryption

## Overview
This repository implements a Fuzzy Semantic Searchable Encryption (FSSE) scheme, as presented in the research paper ["Fuzzy Semantic Searchable Encryption for Privacy-Preserving Document Retrieval"](https://ieeexplore.ieee.org/document/8957445) published in IEEE by **GUOXIU LIU**. The system uses a combination of encryption techniques and secure OTP (One-Time Password) mechanisms to ensure data privacy and security. The project is designed to allow encrypted document storage and retrieval with advanced keyword-based search functionalities. It also incorporates forward secrecy and time-based token updating to secure access to encrypted data.

Key features of the project:
- **AES Encryption** for document confidentiality.
- **Keyword Fingerprint Generation** for semantic search.
- **Database Integration** for storing metadata and encrypted data.
- **OTP-based User Authentication** to enable forward secrecy.
- **Word Fingerprinting** for word-level search accuracy.
  
## Project Components
- **fsse_upload_encrypt.py**: Main script to perform encryption, OTP generation, keyword fingerprinting, and metadata saving.
  
### Functionality
1. **User Authentication**: The system ensures that each user is authenticated using OTP and generates a time-based secret.
2. **Document Encryption**: Files are encrypted using AES encryption, and the key is securely stored.
3. **Keyword Fingerprint Generation**: Keywords from the document are hashed for fast search retrieval.
4. **Metadata Storage**: Metadata including encrypted content and user information is stored in a MySQL database.
5. **Word Hashing**: Individual words within the document are hashed to create fingerprints for granular searches.
6. **Forward Secrecy with PyOTP**: The system uses PyOTP to generate time-based OTP secrets, enhancing security.

### Database Integration
The system integrates with a MySQL database to store user information, metadata, and word fingerprints. The following tables are used:
- **user_auth**: Stores user authentication details along with OTP secrets.
- **document_metadata**: Stores metadata of encrypted documents.
- **user_documents**: Tracks the documents uploaded by each user.
- **word_fingerprints**: Stores the fingerprints of individual words within documents.

 ### Workflow

**1. User Authentication & Registration**

When a user uploads a file, we check if they exist in the user_auth table.

If not, we generate a new PyOTP secret and store it in the database.

This ensures that each user is uniquely identified and authenticated before uploading.

**2. Keyword Fingerprint Generation**

The system generates a SHA-256 fingerprint of the provided keyword for secure indexing.

**3. Document Encryption**

The document is encrypted using AES-GCM with a randomly generated 128-bit key.

The encrypted data, nonce, and authentication tag are stored securely.

**4. Metadata Storage in MySQL (Private Cloud)**

Stores the filename, AES encryption key (base64-encoded), keyword fingerprint, and plaintext (optional) in document_metadata.

The user_documents table tracks which users uploaded which documents.

**5. Encrypted Document Storage in Public Cloud**

The encrypted document is saved as a .json file in a public_cloud/ directory.

**6. Word Extraction & Secure Indexing**

Extracts words from the document and hashes each word using SHA-256.

These hashed words are stored in the word_fingerprints table for searchability.

**7. Full-Text Search Support**

MySQL’s full-text indexing allows searching within document_metadata.

**8. Access Control & Decryption**

When retrieving a document, the system verifies the user's identity and decrypts the document if authorized.

### How to Use
1. **Set Up the Database**:
   - Create a MySQL database called `FSSE_DB` and set up the following tables:
     - `user_auth`
     - `document_metadata`
     - `user_documents`
     - `word_fingerprints`
  ```sql
    CREATE DATABASE IF NOT EXISTS FSSE_DB;
    USE FSSE_DB;

    -- User Authentication Table (No Changes)
    CREATE TABLE IF NOT EXISTS user_auth (
        user_id VARCHAR(255) PRIMARY KEY,
        otp_secret VARCHAR(255) NOT NULL
    );

    -- Document Metadata Table (No Changes, added user_id if it's meant to be used in this table)
    CREATE TABLE IF NOT EXISTS document_metadata (
        file_name VARCHAR(255) PRIMARY KEY,
        keyword_fp VARCHAR(1024) NOT NULL,
        aes_key VARCHAR(255) NOT NULL,
        file_content TEXT,
        user_id VARCHAR(255),  -- New column for user_id if it's necessary here
        FOREIGN KEY (user_id) REFERENCES user_auth(user_id)  -- Link the user_id with user_auth table
    );

    -- Table to Track User's Document Uploads
    CREATE TABLE IF NOT EXISTS user_documents (
        doc_id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(255),
        file_name VARCHAR(255),
        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES user_auth(user_id),
        FOREIGN KEY (file_name) REFERENCES document_metadata(file_name)
    );

    -- Table for Storing Word Fingerprints (New)
    CREATE TABLE IF NOT EXISTS word_fingerprints (
        file_name VARCHAR(255),
        word VARCHAR(255),
        fingerprint VARCHAR(1024),
        PRIMARY KEY (file_name, word),
        FOREIGN KEY (file_name) REFERENCES document_metadata(file_name)
    );

    -- Add a full-text index on file_name and file_content in document_metadata
    ALTER TABLE document_metadata ADD FULLTEXT(file_name);
    --You'll get an error for this above query leave it
    ALTER TABLE document_metadata ADD FULLTEXT(file_content);
```

2. **Run the Script**:
   - Configure the database connection in the `fsse_upload_encrypt.py` file.
   - Run the script by calling the `handle_file_upload()` function to upload and encrypt a document:
   
   ```python
   handle_file_upload(
       file_name="example_file.txt",
       plaintext="Your document content goes here.",
       keyword="your keyword",
       user_id="user123"
   )
   ```

3. **Files Saved**:
   - The encrypted document is saved in the `public_cloud/` directory.
   - Metadata and word fingerprints are saved in the MySQL database.

### Requirements
- Python 3.x
- Libraries:
  - `pyotp`
  - `mysql-connector`
  - `pycryptodome`
  - `re`
- MySQL Server

### How to run:
- run user.py, private_server.py, public_server.py simulatneously
- make sure you have sql server running with the tables
- (some times the private_server.py terminal goes blank so to avoid that switch to private_server terminal as soon as you give query in user)
;; defsrc is still necessary
(defcfg
  process-unmapped-keys yes
)

(defsrc
  caps a s d f j k l ;
)
(defvar
  tap-time 150
  hold-time 200
)

(defalias
  escctrl (tap-hold 50 200 esc lctl)
  a (tap-hold $tap-time $hold-time a lmet)
  s (tap-hold $tap-time $hold-time s lalt)
  d (tap-hold $tap-time $hold-time d lsft)
  f (tap-hold $tap-time $hold-time f lctl)
  j (tap-hold $tap-time $hold-time j rctl)
  k (tap-hold $tap-time $hold-time k rsft)
  l (tap-hold $tap-time $hold-time l ralt)
  ; (tap-hold $tap-time $hold-time ; rmet)
)

(deflayer base
  @escctrl @a @s @d @f @j @k @l @;
)
