# FSSE - Fuzzy Semantic Searchable Encryption

## Overview
This repository implements a **Fuzzy Semantic Searchable Encryption (FSSE)** scheme using a combination of encryption techniques and secure OTP (One-Time Password) mechanisms to ensure data privacy and security. The system is designed to allow encrypted document storage and retrieval with advanced keyword-based search functionalities. The project incorporates forward secrecy and the use of time-based token updating to secure access to encrypted data. 

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
        keyword_fp VARCHAR(255) NOT NULL,
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
        fingerprint VARCHAR(255),
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
