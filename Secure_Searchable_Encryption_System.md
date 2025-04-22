
# Secure Searchable Encryption System

## Overview
This system provides secure document storage with searchable encryption capabilities. It allows users to:
- Create encrypted documents
- Search documents by keywords without decrypting the entire content
- Share documents with other users on the system
- Perform partial keyword searches

The system uses modern cryptographic techniques including AES-GCM for encryption, PBKDF2 for key derivation, and HMAC for searchable keyword hashes.

## Features
- **Multi-database support**: SQLite, MySQL, PostgreSQL
- **Secure encryption**: AES-256-GCM for document encryption
- **Searchable encryption**: Encrypted keyword search capability
- **Partial matching**: Support for partial keyword searches
- **Access control**: Document sharing between users
- **Audit logging**: Comprehensive operation logging

## System Architecture

### Core Components
1. **DatabaseManager**: Handles database connections and queries
2. **SecureSearchableEncryption**: Core encryption and document management
3. **EnhancedSearchableEncryption**: Extends functionality with partial keyword search

### Database Schema
- **users**: Stores user credentials and encryption keys
- **documents**: Contains encrypted documents and keyword hashes
- **document_access**: Manages document sharing permissions
- **keyword_trigrams**: Supports partial keyword searches (enhanced version)

## Installation

### Requirements
- Python 3.8+
- Required packages:
  ```
  pip install sqlite3 mysql-connector-python psycopg2-binary cryptography
  ```

### Setup
1. Clone the repository
2. Install dependencies
3. Run the application:
   ```
   python sse_system.py
   ```

## Usage

### Starting the Application
1. Select database type (SQLite, MySQL, or PostgreSQL)
2. Provide connection details
3. Choose to login as new or existing user

### Main Menu Options
1. **Add Document**: Store a new encrypted document with keywords
2. **Search Document**: Find documents containing specific keywords
3. **Delete Document**: Remove a document and all associated data
4. **List Documents**: View all documents accessible to current user
5. **View Document**: Decrypt and view a specific document
6. **Share Document**: Grant another user access to a document
7. **Partial Keyword Search**: Find documents using partial keyword matches
8. **Exit**: Close the application

## Security Implementation

### Key Components
1. **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations
2. **Document Encryption**: AES-256-GCM with random IVs
3. **Search Tokens**: HMAC-SHA256 of keywords
4. **Key Management**: Each document has unique encryption key

### Security Features
- Constant-time key comparison to prevent timing attacks
- Secure passphrase handling using getpass
- Foreign key constraints for data integrity
- Transaction support for critical operations

## Technical Details

### Encryption Process
1. User provides passphrase which is used to derive a Key Encryption Key (KEK)
2. Each document gets a unique Document Encryption Key (DEK)
3. DEK is encrypted with KEK and stored in document_access table
4. Document content is encrypted with DEK using AES-GCM

### Search Implementation
- Keywords are hashed using HMAC with KEK as the key
- Search compares HMAC of search term with stored keyword hashes
- Partial matching uses trigrams (3-character sequences) of keywords

## Troubleshooting

### Common Issues
1. **Database connection problems**:
   - Verify connection parameters
   - Check database server is running (for MySQL/PostgreSQL)

2. **User authentication failures**:
   - Ensure correct passphrase is entered
   - Check database contains expected user records

3. **Document access issues**:
   - Verify document exists and user has permissions
   - Check encryption keys are valid

### Debugging
Enable debug logging by changing:
```python
logging.basicConfig(level=logging.DEBUG)
```
