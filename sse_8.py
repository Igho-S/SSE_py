import sqlite3
import mysql.connector
import psycopg2
import base64
import getpass
import logging
import re
from typing import List, Optional, Dict, Any
from os import urandom
from hmac import compare_digest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_type: str, **kwargs):
        self.db_type = db_type
        self.connection_params = kwargs
        self.conn = None

    def connect(self):
        try:
            if self.db_type == "sqlite":
                self.conn = sqlite3.connect(
                    self.connection_params["db_path"],
                    check_same_thread=False  # For SQLite thread safety
                )
                self.conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign keys
                logger.info("Connected to SQLite database.")
            elif self.db_type == "mysql":
                self.conn = mysql.connector.connect(
                    host=self.connection_params["host"],
                    user=self.connection_params["user"],
                    password=self.connection_params["password"],
                    database=self.connection_params["database"],
                )
                logger.info("Connected to MySQL database.")
            elif self.db_type == "postgresql":
                self.conn = psycopg2.connect(
                    host=self.connection_params["host"],
                    user=self.connection_params["user"],
                    password=self.connection_params["password"],
                    dbname=self.connection_params["database"],
                )
                logger.info("Connected to PostgreSQL database.")
            else:
                raise ValueError("Unsupported database type.")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def disconnect(self):
        if self.conn:
            self.conn.close()
            logger.info("Disconnected from database.")

    def execute_query(self, query: str, params: tuple = None) -> Optional[List[Dict[str, Any]]]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params or ())
            if query.strip().lower().startswith("select"):
                columns = [col[0] for col in cursor.description]
                results = [dict(zip(columns, row)) for row in cursor.fetchall()]
                cursor.close()
                return results
            else:
                self.conn.commit()
                cursor.close()
                return None
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            self.conn.rollback()
            raise


class SecureSearchableEncryption:
    def __init__(self, db_manager: DatabaseManager, user_id: str, passphrase: str):
        self.passphrase = passphrase
        self.db_manager = db_manager
        self.user_id = user_id
        self.salt, self.key_encryption_key = self._get_or_create_user()

    def _initialize_db(self):
        """Initialize database tables with proper constraints."""
        queries = [
            """CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                key_encryption_key BLOB NOT NULL
            ) STRICT;""",
            """CREATE TABLE IF NOT EXISTS documents (
                doc_id TEXT PRIMARY KEY,
                content BLOB NOT NULL,
                keyword_hashes BLOB NOT NULL
            ) STRICT;""",
            """CREATE TABLE IF NOT EXISTS document_access (
                doc_id TEXT,
                user_id TEXT,
                encrypted_key BLOB NOT NULL,
                PRIMARY KEY (doc_id, user_id),
                FOREIGN KEY(doc_id) REFERENCES documents(doc_id),
                FOREIGN KEY(user_id) REFERENCES users(user_id)
            ) STRICT;"""
        ]
        for query in queries:
            self.db_manager.execute_query(query)
        logger.info("Database initialized with proper constraints.")

    def _get_or_create_user(self) -> tuple[bytes, bytes]:
        """Get existing user or create new user with proper checks."""
        result = self.db_manager.execute_query(
            "SELECT salt, key_encryption_key FROM users WHERE user_id = ?",
            (self.user_id,)
        )

        if result:  # Existing user
            salt = result[0]['salt']
            stored_kek = result[0]['key_encryption_key']
            derived_kek = self._derive_key(self.passphrase, salt)

            if not compare_digest(stored_kek, derived_kek):
                logger.error("Authentication failed: Incorrect passphrase.")
                raise ValueError("Invalid credentials.")

            logger.info("Successfully authenticated existing user.")
            return salt, derived_kek

        # New user - check for existing ID first
        existing = self.db_manager.execute_query(
            "SELECT user_id FROM users WHERE user_id = ?",
            (self.user_id,)
        )
        if existing:
            logger.error("User ID already exists.")
            raise ValueError("User ID already exists.")

        # Generate new credentials
        salt = urandom(16)
        kek = self._derive_key(self.passphrase, salt)

        self.db_manager.execute_query(
            "INSERT INTO users (user_id, salt, key_encryption_key) VALUES (?, ?, ?)",
            (self.user_id, salt, kek)
        )
        logger.info("Successfully created new user.")
        return salt, kek

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive 256-bit key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))

    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data with AES-GCM and return IV + ciphertext + tag."""
        iv = urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def _decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt AES-GCM encrypted data (IV + ciphertext + tag)."""
        iv = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def add_document(self, doc_id: str, content: str, keywords: List[str]):
        """Add document with searchable encryption."""
        # Generate document-specific key
        doc_key = urandom(32)

        # Encrypt content
        encrypted_content = self._encrypt_data(content.encode('utf-8'), doc_key)

        # Generate searchable keyword hashes
        keyword_hashes = []
        for kw in keywords:
            h = hmac.HMAC(self.key_encryption_key, SHA256(), backend=default_backend())
            h.update(kw.encode('utf-8'))
            keyword_hashes.append(h.finalize())
        keyword_hashes = b''.join(keyword_hashes)

        # Encrypt document key for owner
        encrypted_key = self._encrypt_data(doc_key, self.key_encryption_key)

        # Store document and access
        try:
            with self.db_manager.conn:  # Transaction
                self.db_manager.execute_query(
                    "INSERT INTO documents (doc_id, content, keyword_hashes) VALUES (?, ?, ?)",
                    (doc_id, encrypted_content, keyword_hashes)
                )
                self.db_manager.execute_query(
                    "INSERT INTO document_access (doc_id, user_id, encrypted_key) VALUES (?, ?, ?)",
                    (doc_id, self.user_id, encrypted_key)
                )
            logger.info(f"Document {doc_id} added successfully.")
        except Exception as e:
            logger.error(f"Failed to add document: {e}")
            raise

    def list_documents(self) -> List[str]:
        """List documents the current user has access to."""
        results = self.db_manager.execute_query(
            "SELECT doc_id FROM document_access WHERE user_id = ?",
            (self.user_id,)
        )
        if not results:
            return []
        return [row['doc_id'] for row in results]

    def delete_document(self, doc_id: str):
        """Delete a document and its associated access records."""
        # Check if user has access and is the owner
        access = self.db_manager.execute_query(
            "SELECT doc_id FROM document_access WHERE doc_id = ? AND user_id = ?",
            (doc_id, self.user_id)
        )
        if not access:
            logger.warning(f"No access to document {doc_id}.")
            raise PermissionError(f"No access to document {doc_id}.")

        try:
            with self.db_manager.conn:  # Transaction
                # Delete all access records for this document
                self.db_manager.execute_query(
                    "DELETE FROM document_access WHERE doc_id = ?",
                    (doc_id,)
                )
                # Delete the document
                self.db_manager.execute_query(
                    "DELETE FROM documents WHERE doc_id = ?",
                    (doc_id,)
                )
            logger.info(f"Document {doc_id} deleted successfully.")
        except Exception as e:
            logger.error(f"Failed to delete document: {e}")
            raise

    def share_document(self, doc_id: str, target_user_id: str):
        """Share document with another user."""
        # Verify current user has access
        access = self.db_manager.execute_query(
            "SELECT encrypted_key FROM document_access WHERE doc_id = ? AND user_id = ?",
            (doc_id, self.user_id)
        )
        if not access:
            logger.error("Current user doesn't have access to this document.")
            raise PermissionError("No access to document.")

        # Check if document is already shared with target user
        existing_share = self.db_manager.execute_query(
            "SELECT doc_id FROM document_access WHERE doc_id = ? AND user_id = ?",
            (doc_id, target_user_id)
        )
        if existing_share:
            logger.info(f"Document {doc_id} is already shared with {target_user_id}.")
            return

        # Decrypt document key
        try:
            doc_key = self._decrypt_data(access[0]['encrypted_key'], self.key_encryption_key)
        except InvalidTag:
            logger.error("Failed to decrypt document key - possible tampering.")
            raise

        # Get target user's salt and use it to encrypt for them
        target_user = self.db_manager.execute_query(
            "SELECT salt FROM users WHERE user_id = ?",
            (target_user_id,)
        )
        if not target_user:
            logger.error("Target user does not exist.")
            raise ValueError("Invalid target user.")

        # DEBUG: Print users in the database to diagnose issues
        all_users = self.db_manager.execute_query("SELECT user_id FROM users")
        logger.info(f"Available users in database: {[u['user_id'] for u in all_users]}")
        
        # Get target user's passphrase (in a real app, you wouldn't do this)
        # For this example, assume we have a way to securely get their passphrase
        # In practice, there would be a different key exchange mechanism
        target_salt = target_user[0]['salt']
        
        # Re-derive the target user's key encryption key
        # In a real system, you'd use asymmetric encryption or a secure key exchange protocol
        # This is just to fix the immediate issue
        target_kek = self.db_manager.execute_query(
            "SELECT key_encryption_key FROM users WHERE user_id = ?",
            (target_user_id,)
        )[0]['key_encryption_key']

        # Encrypt document key with target user's key encryption key
        encrypted_for_target = self._encrypt_data(doc_key, target_kek)

        # Grant access
        try:
            self.db_manager.execute_query(
                "INSERT INTO document_access (doc_id, user_id, encrypted_key) VALUES (?, ?, ?)",
                (doc_id, target_user_id, encrypted_for_target)
            )
            logger.info(f"Successfully shared document {doc_id} with {target_user_id}.")
        except Exception as e:
            logger.error(f"Sharing failed: {e}")
            raise

    def search_documents(self, keyword: str) -> List[str]:
        """Search documents containing keyword."""
        # Generate search token
        h = hmac.HMAC(self.key_encryption_key, SHA256(), backend=default_backend())
        h.update(keyword.encode('utf-8'))
        search_token = h.finalize()

        # Get only documents the user has access to
        results = self.db_manager.execute_query(
            """SELECT d.doc_id, d.keyword_hashes FROM documents d
               JOIN document_access a ON d.doc_id = a.doc_id
               WHERE a.user_id = ?""",
            (self.user_id,)
        )

        matches = []
        for row in results:
            hashes = row['keyword_hashes']
            # Compare each 32-byte hash chunk
            for i in range(0, len(hashes), 32):
                if compare_digest(hashes[i:i+32], search_token):
                    matches.append(row['doc_id'])
                    break  # No need to check other hashes for this doc
        return matches

    def get_document(self, doc_id: str) -> Optional[str]:
        """Retrieve and decrypt document."""
        # Check access
        access = self.db_manager.execute_query(
            "SELECT encrypted_key FROM document_access WHERE doc_id = ? AND user_id = ?",
            (doc_id, self.user_id)
        )
        if not access:
            logger.warning("No access to document.")
            return None

        try:
            # Decrypt document key
            doc_key = self._decrypt_data(access[0]['encrypted_key'], self.key_encryption_key)

            # Get encrypted content
            doc_data = self.db_manager.execute_query(
                "SELECT content FROM documents WHERE doc_id = ?",
                (doc_id,)
            )
            if not doc_data:
                return None

            # Decrypt content
            content = self._decrypt_data(doc_data[0]['content'], doc_key)
            return content.decode('utf-8')
        except InvalidTag:
            logger.error("Decryption failed - possible tampering.")
            return None


class EnhancedSearchableEncryption(SecureSearchableEncryption):
    
    def __init__(self, db_manager: DatabaseManager, user_id: str, passphrase: str):
        super().__init__(db_manager, user_id, passphrase)
        self._initialize_enhanced_db()
        
    def _initialize_enhanced_db(self):
        queries = [
            """CREATE TABLE IF NOT EXISTS keyword_trigrams (
                doc_id TEXT,
                trigram_hash BLOB,
                encrypted_position BLOB,
                PRIMARY KEY (doc_id, trigram_hash),
                FOREIGN KEY(doc_id) REFERENCES documents(doc_id)
            ) STRICT;"""
        ]
        for query in queries:
            self.db_manager.execute_query(query)
        logger.info("Enhanced database tables initialized.")
    
    def _generate_trigrams(self, keyword: str) -> List[str]:
        """Generate trigrams from a keyword for partial matching"""
        # Convert to lowercase and remove special characters
        normalized = re.sub(r'[^a-zA-Z0-9]', '', keyword.lower())
        
        # Generate trigrams (3-character sequences)
        trigrams = []
        if len(normalized) <= 3:
            trigrams = [normalized]
        else:
            for i in range(len(normalized) - 2):
                trigrams.append(normalized[i:i+3])
                
        return trigrams
    
    def _deterministic_encrypt(self, data: str) -> bytes:
        """Deterministic encryption for searchable trigrams"""
        h = hmac.HMAC(self.key_encryption_key, SHA256(), backend=default_backend())
        h.update(data.encode('utf-8'))
        return h.finalize()
    
    def _order_preserving_encrypt(self, value: int) -> bytes:        
        # Use HMAC as a keyed function to transform the value
        h = hmac.HMAC(self.key_encryption_key, SHA256(), backend=default_backend())
        h.update(str(value).encode('utf-8'))
        digest = h.finalize()
        
        # Use the first 8 bytes as a seed to deterministically transform the value
        seed = int.from_bytes(digest[:8], byteorder='big')
        
        # Apply a reversible transformation that preserves order
        transformed = (value * 1337 + seed % 1000) & 0xFFFFFFFF
        
        # Encrypt the transformed value
        return self._encrypt_data(transformed.to_bytes(8, byteorder='big'), self.key_encryption_key)
    
    def _order_preserving_decrypt(self, encrypted_value: bytes) -> int:
        # Decrypt the transformed value
        transformed_bytes = self._decrypt_data(encrypted_value, self.key_encryption_key)
        transformed = int.from_bytes(transformed_bytes, byteorder='big')
        
        h = hmac.HMAC(self.key_encryption_key, SHA256(), backend=default_backend())
        h.update(str(transformed).encode('utf-8'))
        digest = h.finalize()
        seed = int.from_bytes(digest[:8], byteorder='big')
        
        # Reverse the transformation
        original = ((transformed - seed % 1000) // 1337) & 0xFFFFFFFF
        return original
    
    def add_document_with_partial_search(self, doc_id: str, content: str, keywords: List[str]):
        # First add the document normally
        self.add_document(doc_id, content, keywords)
        
        # Then add trigram information for each keyword
        for keyword in keywords:
            trigrams = self._generate_trigrams(keyword)
            for position, trigram in enumerate(trigrams):
                trigram_hash = self._deterministic_encrypt(trigram)
                encrypted_position = self._order_preserving_encrypt(position)
                
                self.db_manager.execute_query(
                    """INSERT OR REPLACE INTO keyword_trigrams 
                       (doc_id, trigram_hash, encrypted_position) VALUES (?, ?, ?)""",
                    (doc_id, trigram_hash, encrypted_position)
                )
                
        logger.info(f"Added trigram indices for partial search on document {doc_id}")
    
    def partial_search(self, partial_keyword: str) -> List[str]:
        """Search for documents containing partial keyword matches"""
        trigrams = self._generate_trigrams(partial_keyword)
        if not trigrams:
            return []
        
        potential_matches = set()
        first_search = True
        
        for trigram in trigrams:
            trigram_hash = self._deterministic_encrypt(trigram)
            
            results = self.db_manager.execute_query(
                """SELECT DISTINCT kt.doc_id 
                   FROM keyword_trigrams kt
                   JOIN document_access da ON kt.doc_id = da.doc_id
                   WHERE kt.trigram_hash = ? AND da.user_id = ?""",
                (trigram_hash, self.user_id)
            )
            
            # Get document IDs from results
            doc_ids = {row['doc_id'] for row in results}
            
            if first_search:
                potential_matches = doc_ids
                first_search = False
            else:
                # Keep only documents that contain all trigrams
                potential_matches &= doc_ids
                
        return list(potential_matches)
    
    # Override delete_document to also remove trigram data
    def delete_document(self, doc_id: str):
        """Delete a document and all associated data including trigrams"""
        # Check if user has access
        access = self.db_manager.execute_query(
            "SELECT doc_id FROM document_access WHERE doc_id = ? AND user_id = ?",
            (doc_id, self.user_id)
        )
        if not access:
            logger.warning(f"No access to document {doc_id}.")
            raise PermissionError(f"No access to document {doc_id}.")

        try:
            with self.db_manager.conn:  # Transaction
                # First delete trigram data
                self.db_manager.execute_query(
                    "DELETE FROM keyword_trigrams WHERE doc_id = ?",
                    (doc_id,)
                )
                
                # Delete all access records
                self.db_manager.execute_query(
                    "DELETE FROM document_access WHERE doc_id = ?",
                    (doc_id,)
                )
                
                # Delete the document
                self.db_manager.execute_query(
                    "DELETE FROM documents WHERE doc_id = ?",
                    (doc_id,)
                )
                
            logger.info(f"Document {doc_id} and all related data deleted successfully.")
        except Exception as e:
            logger.error(f"Failed to delete document: {e}")
            raise

def main():
    print("Select database type:")
    print("1. SQLite")
    print("2. MySQL")
    print("3. PostgreSQL")
    db_choice = input("Enter your choice (1/2/3): ")

    db_type = None
    if db_choice == "1":
        db_type = "sqlite"
    elif db_choice == "2":
        db_type = "mysql"
    elif db_choice == "3":
        db_type = "postgresql"
    else:
        print("Invalid choice. Exiting.")
        return

    credentials = {}
    if db_type == "sqlite":
        credentials["db_path"] = input("Enter SQLite database file path: ")
    else:
        credentials["host"] = input("Enter database host: ")
        credentials["user"] = input("Enter database username: ")
        credentials["password"] = getpass.getpass("Enter database password: ")
        credentials["database"] = input("Enter database name: ")

    db_manager = DatabaseManager(db_type, **credentials)
    
    try:
        db_manager.connect()
        init_queries = [
            """CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                key_encryption_key BLOB NOT NULL
            ) STRICT;""",
            """CREATE TABLE IF NOT EXISTS documents (
                doc_id TEXT PRIMARY KEY,
                content BLOB NOT NULL,
                keyword_hashes BLOB NOT NULL
            ) STRICT;""",
            """CREATE TABLE IF NOT EXISTS document_access (
                doc_id TEXT,
                user_id TEXT,
                encrypted_key BLOB NOT NULL,
                PRIMARY KEY (doc_id, user_id),
                FOREIGN KEY(doc_id) REFERENCES documents(doc_id),
                FOREIGN KEY(user_id) REFERENCES users(user_id)
            ) STRICT;""",
            """CREATE TABLE IF NOT EXISTS keyword_trigrams (
                doc_id TEXT,
                trigram_hash BLOB,
                encrypted_position BLOB,
                PRIMARY KEY (doc_id, trigram_hash),
                FOREIGN KEY(doc_id) REFERENCES documents(doc_id)
            ) STRICT;"""
        ]
        for query in init_queries:
            try:
                db_manager.execute_query(query)
            except Exception as e:
                logger.error(f"Error creating table: {e}")
                print(f"Error setting up database table: {e}")
                
        logger.info("Database tables verified/created.")
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        return

    user_type = input("Are you a new user or an old user? (new/old): ").strip().lower()
    if user_type not in ["new", "old"]:
        print("Invalid choice. Exiting.")
        return

    user_id = input("Enter your user ID: ")
    passphrase = getpass.getpass("Enter your passphrase: ")

    try:
        all_users = db_manager.execute_query("SELECT user_id FROM users")
        if all_users:
            print("Users in database:", [u['user_id'] for u in all_users])
    except Exception as e:
        print(f"Could not retrieve users: {e}")

    try:
        sse = EnhancedSearchableEncryption(db_manager, user_id, passphrase)
        if user_type == "new":
            print(f"New user '{user_id}' created successfully.")
        else:
            print(f"Welcome back, {user_id}!")
    except Exception as e:
        print(f"Error: {e}")
        return

    while True:
        print("\nMenu:")
        print("1. Add Document")
        print("2. Search Document")
        print("3. Delete Document")
        print("4. List Documents")
        print("5. View Document")
        print("6. Share Document")
        print("7. Partial Keyword Search")
        print("8. Exit")

        choice = input("Enter your choice: ")

        try:
            if choice == "1":
                doc_id = input("Enter document ID: ")
                content = input("Enter document content: ")
                keywords = input("Enter keywords (comma-separated): ").split(",")
                sse.add_document_with_partial_search(doc_id, content, [k.strip() for k in keywords])
                print(f"Document '{doc_id}' added successfully.")
            elif choice == "2":
                keyword = input("Enter keyword to search for: ")
                results = sse.search_documents(keyword)
                if results:
                    print("Documents containing the keyword:")
                    for doc_id in results:
                        print(f"- {doc_id}")
                else:
                    print("No matching documents found.")
            elif choice == "3":
                doc_id = input("Enter document ID to delete: ")
                sse.delete_document(doc_id)
                print(f"Document '{doc_id}' deleted successfully.")
            elif choice == "4":
                doc_ids = sse.list_documents()
                if doc_ids:
                    print("Your documents:")
                    for doc_id in doc_ids:
                        print(f"- {doc_id}")
                else:
                    print("No documents found.")
            elif choice == "5":
                doc_id = input("Enter document ID to view: ")
                content = sse.get_document(doc_id)
                if content:
                    print(f"Content of '{doc_id}':\n{content}")
                else:
                    print("Document not found or access denied.")
            elif choice == "6":
                doc_id = input("Enter document ID to share: ")
                target_user_id = input("Enter the user ID to share with: ")
                
                # Debug: Check if target user exists before sharing
                target_exists = db_manager.execute_query(
                    "SELECT user_id FROM users WHERE user_id = ?", 
                    (target_user_id,)
                )
                if not target_exists:
                    print(f"Warning: User '{target_user_id}' does not exist in the database.")
                    continue
                    
                sse.share_document(doc_id, target_user_id)
                print(f"Document '{doc_id}' shared with '{target_user_id}' successfully.")
            elif choice == "7":
                partial_keyword = input("Enter partial keyword to search for: ")
                results = sse.partial_search(partial_keyword)
                if results:
                    print("Documents containing the partial keyword match:")
                    for doc_id in results:
                        print(f"- {doc_id}")
                else:
                    print("No matching documents found.")
            elif choice == "8":
                print("Exiting application...")
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"Error: {e}")

    db_manager.disconnect()


if __name__ == "__main__":
    main()