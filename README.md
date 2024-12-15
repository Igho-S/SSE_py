# SSE_py
SSE implementation inspired by the SOPHOS scheme

# Secure Searchable Encryption (SSE) Database

This project implements a **Secure Searchable Encryption (SSE)** database system using Python. The system enables encrypted storage and secure keyword-based search over encrypted documents. It combines SQLite for storage and cryptography for encryption and keyword hashing.

## Features

1. **Encrypted Document Storage**:
   - AES-GCM encryption ensures confidentiality and integrity of the stored content.

2. **Keyword-Based Search**:
   - Uses HMAC-SHA256 for secure keyword hashing.
   - Supports search without decrypting stored content.

3. **Document Management**:
   - Add, delete, view, and list documents.

4. **Secure Key Derivation**:
   - Passphrase-based key generation using PBKDF2-HMAC-SHA256 with a unique salt per database.

5. **SQLite Backend**:
   - Persistent storage for encrypted documents and metadata.

## How It Works

1. **Encryption**:
   - Documents are encrypted using AES-GCM with a derived encryption key.
   - Random IVs and authentication tags ensure data integrity and uniqueness.

2. **Keyword Hashing**:
   - Keywords are hashed using HMAC with the encryption key.
   - Only the hash is stored, enabling keyword search without revealing plaintext keywords.

3. **Database Storage**:
   - Documents, their encrypted contents, and keyword hashes are stored in SQLite tables.

4. **Passphrase Protection**:
   - User-provided passphrase is used to derive the encryption key.
   - A unique salt ensures security against passphrase reuse.

## Installation

### Prerequisites

- **Python 3.8+**
- **Dependencies**:
  Install the required Python packages:

  ```bash
  pip install cryptography
  ```

### Usage

1. Clone or download the project.
2. Save the code in a file (e.g., `secure_sse.py`).
3. Run the script using:

   ```bash
   python secure_sse.py
   ```

## Application Menu

When you run the script, you'll interact with a menu offering the following options:

1. **Add Document**:
   - Input a document ID, content, and associated keywords.
   - Data is encrypted and stored securely.

2. **Search Document**:
   - Search for documents by a keyword.
   - Returns matching document IDs without decrypting stored data.

3. **Delete Document**:
   - Remove a document from the database by its ID.

4. **List Documents**:
   - View all stored document IDs.

5. **View Document**:
   - Decrypt and display the content of a document by its ID.

6. **Exit**:
   - Exit the application.

## Code Structure

### Classes

- **`SecureSearchableEncryption`**:
  Implements the core functionality, including:
  - Key derivation.
  - Document encryption/decryption.
  - Keyword hashing.
  - SQLite integration.

### Key Methods

- **`add_document(doc_id, content, keywords)`**:
  Encrypts and stores a document with associated keywords.

- **`search_document(keyword)`**:
  Searches for documents matching the hashed keyword.

- **`delete_document(doc_id)`**:
  Deletes a document by ID.

- **`list_documents()`**:
  Lists all stored document IDs.

- **`view_document2(doc_id)`**:
  Decrypts and displays a document's content.

### Database Tables

1. **`settings`**:
   - Stores the unique salt for key derivation.

2. **`documents`**:
   - Stores encrypted content and hashed keywords.

## Security Considerations

- **Passphrase Management**:
  Ensure a strong, unique passphrase is used.

- **Database Backup**:
  Backup the database file (`sse_secure.db`) securely.

- **Key Security**:
  The encryption key is derived from the passphrase and is not stored.

- **Salt**:
  A unique salt prevents pre-computation attacks.

## Example Usage

1. **Add a Document**:

   Input:
   ```
   Enter document ID: doc123
   Enter document content: Secure content
   Enter keywords (comma-separated): secret, sensitive
   ```

   Output:
   ```
   Document doc123 added successfully.
   ```

2. **Search for a Document**:

   Input:
   ```
   Enter keyword to search for: secret
   ```

   Output:
   ```
   Documents containing the keyword:
   - doc123
   ```

3. **View a Document**:

   Input:
   ```
   Enter document ID to view: doc123
   ```

   Output:
   ```
   Content of 'doc123':
   Secure content
   ```

4. **Delete a Document**:

   Input:
   ```
   Enter document ID to delete: doc123
   ```

   Output:
   ```
   Document doc123 deleted successfully.
   ```

## Notes

- The application does not support passphrase recovery.
- Use secure storage practices for the `sse_secure.db` file.
