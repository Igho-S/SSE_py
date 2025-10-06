# client.py

import base64
import getpass
import logging
import re
import time
import hashlib
from typing import List, Optional, Dict, Any, Tuple
from os import urandom
from hmac import compare_digest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
import requests
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RemoteDatabaseManager:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')

    def connect(self):
        response = requests.post(f"{self.server_url}/connect")
        if response.status_code != 200:
            raise Exception(response.json().get('error', 'Failed to connect'))

    def disconnect(self):
        response = requests.post(f"{self.server_url}/disconnect")
        if response.status_code != 200:
            logger.warning("Failed to disconnect cleanly")

    def start_transaction(self):
        response = requests.post(f"{self.server_url}/start_transaction")
        if response.status_code != 200:
            raise Exception(response.json().get('error', 'Failed to start transaction'))

    def commit(self):
        response = requests.post(f"{self.server_url}/commit")
        if response.status_code != 200:
            raise Exception(response.json().get('error', 'Failed to commit'))

    def rollback(self):
        response = requests.post(f"{self.server_url}/rollback")
        if response.status_code != 200:
            raise Exception(response.json().get('error', 'Failed to rollback'))

    def execute_query(self, query: str, params: tuple = None) -> Optional[List[Dict[str, Any]]]:
        params_serial = [serialize_param(p) for p in (params or ())]
        data = {'query': query, 'params': params_serial}
        response = requests.post(f"{self.server_url}/execute_query", json=data)
        if response.status_code == 200:
            resp_json = response.json()
            result = resp_json['result']
            if result is not None:
                return [{k: deserialize_value(v) for k, v in row.items()} for row in result]
            return None
        else:
            raise Exception(response.json().get('error', 'Failed to execute query'))

def serialize_param(p):
    if isinstance(p, bytes):
        return {'type': 'bytes', 'value': base64.b64encode(p).decode('utf-8')}
    else:
        return {'type': 'other', 'value': p}

def deserialize_value(sv):
    if sv['type'] == 'bytes':
        return base64.b64decode(sv['value'])
    else:
        return sv['value']

class ForwardPrivacySearchableEncryption:
    def __init__(self, db_manager: RemoteDatabaseManager, user_id: str, passphrase: str):
        self.passphrase = passphrase
        self.db_manager = db_manager
        self.user_id = user_id
        self.is_new_user = False
        self.current_session_id = None
        self.current_session_key = None
        self.archive_access_key = None
        self._initialize_db()
        self.salt, self.key_encryption_key, self.is_new_user = self._get_or_create_user()
        self._start_new_session()

    def _initialize_db(self):
        """Initialize database tables with forward privacy support."""
        queries = [
            """CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(255) PRIMARY KEY,
                salt BINARY(16) NOT NULL,
                key_encryption_key BINARY(32) NOT NULL,
                archive_key_hash BINARY(32),
                current_session_id VARCHAR(255)
            );""",
            
            """CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                session_key_encrypted BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY(user_id) REFERENCES users(user_id)
            );""",
            
            """CREATE TABLE IF NOT EXISTS documents (
                doc_id VARCHAR(255),
                user_id VARCHAR(255),
                session_id VARCHAR(255) NOT NULL,
                content BLOB NOT NULL,
                keyword_hashes BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, doc_id),
                FOREIGN KEY(user_id) REFERENCES users(user_id),
                FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            );""",
            
            """CREATE TABLE IF NOT EXISTS document_access (
                doc_id VARCHAR(255),
                user_id VARCHAR(255),
                session_id VARCHAR(255),
                encrypted_key BLOB NOT NULL,
                PRIMARY KEY (doc_id, user_id),
                FOREIGN KEY(user_id, doc_id) REFERENCES documents(user_id, doc_id),
                FOREIGN KEY(user_id) REFERENCES users(user_id),
                FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            );""",
            
            """CREATE TABLE IF NOT EXISTS keyword_trigrams (
                doc_id VARCHAR(255),
                user_id VARCHAR(255),
                session_id VARCHAR(255),
                trigram_hash BINARY(32),
                encrypted_position BLOB,
                PRIMARY KEY (user_id, doc_id, trigram_hash),
                FOREIGN KEY(user_id, doc_id) REFERENCES documents(user_id, doc_id),
                FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            );"""
        ]
        for query in queries:
            self.db_manager.execute_query(query)
        logger.info("Forward privacy database initialized.")

    def _get_or_create_user(self) -> tuple[bytes, bytes, bool]:
        """Get existing user or create new user with proper checks."""
        result = self.db_manager.execute_query(
            "SELECT salt, key_encryption_key, archive_key_hash FROM users WHERE user_id = %s",
            (self.user_id,)
        )

        is_new = False
        if result:
            salt = result[0]['salt']
            stored_kek = result[0]['key_encryption_key']
            derived_kek = self._derive_key(self.passphrase, salt)

            if not compare_digest(stored_kek, derived_kek):
                logger.error("Authentication failed: Incorrect passphrase.")
                raise ValueError("Invalid credentials.")

            logger.info("Successfully authenticated existing user.")
            return salt, derived_kek, is_new
        else:
            is_new = True

        salt = urandom(16)
        kek = self._derive_key(self.passphrase, salt)

        self.db_manager.execute_query(
            "INSERT INTO users (user_id, salt, key_encryption_key) VALUES (%s, %s, %s)",
            (self.user_id, salt, kek)
        )
        logger.info("Successfully created new user.")
        return salt, kek, is_new

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

    def _start_new_session(self):
        """Start a new session for forward privacy."""
        self.current_session_id = base64.urlsafe_b64encode(urandom(16)).decode('utf-8')
        self.current_session_key = urandom(32)
        
        # Encrypt session key with user's KEK
        encrypted_session_key = self._encrypt_data(self.current_session_key, self.key_encryption_key)
        
        # Store session
        self.db_manager.execute_query(
            "INSERT INTO sessions (session_id, user_id, session_key_encrypted, created_at) VALUES (%s, %s, %s, %s)",
            (self.current_session_id, self.user_id, encrypted_session_key, int(time.time()))
        )
        
        # Update user's current session
        self.db_manager.execute_query(
            "UPDATE users SET current_session_id = %s WHERE user_id = %s",
            (self.current_session_id, self.user_id)
        )
        
        logger.info(f"Started new session: {self.current_session_id}")

    def set_archive_passcode(self, old_passcode: Optional[str], new_passcode: str):
        """Set or change the archive passcode with verification of old passcode if exists."""
        result = self.db_manager.execute_query(
            "SELECT archive_key_hash FROM users WHERE user_id = %s",
            (self.user_id,)
        )
        
        if result and result[0]['archive_key_hash']:
            # Existing passcode - verify old passcode
            if not old_passcode:
                raise ValueError("Old archive passcode is required to change it.")
                
            stored_hash = result[0]['archive_key_hash']
            provided_hash = hashlib.pbkdf2_hmac('sha256', 
                                              old_passcode.encode('utf-8'), 
                                              self.salt, 
                                              600000)
            
            if not compare_digest(stored_hash, provided_hash):
                raise ValueError("Invalid old archive passcode.")
        else:
            # First time setting passcode - verify main passphrase
            if not old_passcode:
                raise ValueError("Main passphrase is required for first-time archive passcode setup.")
            
            # Verify main passphrase
            derived_kek = self._derive_key(old_passcode, self.salt)
            if not compare_digest(self.key_encryption_key, derived_kek):
                raise ValueError("Invalid main passphrase.")
        
        # Hash the new archive passcode
        archive_key_hash = hashlib.pbkdf2_hmac('sha256', 
                                             new_passcode.encode('utf-8'), 
                                             self.salt, 
                                             600000)
        
        # Store the hash
        self.db_manager.execute_query(
            "UPDATE users SET archive_key_hash = %s WHERE user_id = %s",
            (archive_key_hash, self.user_id)
        )
        
        # Derive the actual archive access key
        self.archive_access_key = self._derive_key(new_passcode, self.salt)
        logger.info("Archive passcode set/updated successfully.")

    def unlock_archive_access(self, archive_passcode: str) -> bool:
        """Unlock access to archived sessions with archive passcode."""
        # Get stored hash
        result = self.db_manager.execute_query(
            "SELECT archive_key_hash FROM users WHERE user_id = %s",
            (self.user_id,)
        )
        
        if not result or not result[0]['archive_key_hash']:
            logger.warning("No archive passcode set.")
            return False
        
        stored_hash = result[0]['archive_key_hash']
        
        # Verify passcode
        provided_hash = hashlib.pbkdf2_hmac('sha256', 
                                           archive_passcode.encode('utf-8'), 
                                           self.salt, 
                                           600000)
        
        if compare_digest(stored_hash, provided_hash):
            self.archive_access_key = self._derive_key(archive_passcode, self.salt)
            logger.info("Archive access unlocked successfully.")
            return True
        else:
            logger.warning("Invalid archive passcode.")
            return False

    def _get_session_key(self, session_id: str) -> Optional[bytes]:
        """Get session key for a specific session."""
        if session_id == self.current_session_id:
            return self.current_session_key
        
        # For archived sessions, need archive access
        if not self.archive_access_key:
            logger.warning("Archive access required for old sessions.")
            return None
        
        # Get encrypted session key
        result = self.db_manager.execute_query(
            "SELECT session_key_encrypted FROM sessions WHERE session_id = %s AND user_id = %s",
            (session_id, self.user_id)
        )
        
        if not result:
            return None
        
        try:
            # Try to decrypt with archive key
            session_key = self._decrypt_data(result[0]['session_key_encrypted'], self.archive_access_key)
            return session_key
        except:
            # Try with regular KEK (for backward compatibility)
            try:
                session_key = self._decrypt_data(result[0]['session_key_encrypted'], self.key_encryption_key)
                return session_key
            except:
                logger.error("Failed to decrypt session key.")
                return None

    def end_current_session(self):
        """End current session to implement forward privacy."""
        if self.current_session_id:
            self.db_manager.execute_query(
                "UPDATE sessions SET is_active = 0 WHERE session_id = %s",
                (self.current_session_id,)
            )
            
            # Clear current session data from memory
            old_session_id = self.current_session_id
            self.current_session_id = None
            self.current_session_key = None
            
            logger.info(f"Ended session: {old_session_id}")
            
            # Start new session
            self._start_new_session()

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
        """Add document with forward privacy (in current session)."""
        if not self.current_session_key:
            raise ValueError("No active session.")
        
        # Generate document-specific key
        doc_key = urandom(32)

        # Encrypt content with session-specific encryption
        encrypted_content = self._encrypt_data(content.encode('utf-8'), doc_key)

        # Generate searchable keyword hashes using current session key
        keyword_hashes = []
        for kw in keywords:
            h = hmac.HMAC(self.current_session_key, SHA256(), backend=default_backend())
            h.update(kw.encode('utf-8'))
            keyword_hashes.append(h.finalize())
        keyword_hashes = b''.join(keyword_hashes)

        # Encrypt document key with session key
        encrypted_key = self._encrypt_data(doc_key, self.current_session_key)

        # Store document and access
        try:
            self.db_manager.start_transaction()
            self.db_manager.execute_query(
                "INSERT INTO documents (doc_id, user_id, session_id, content, keyword_hashes, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                (doc_id, self.user_id, self.current_session_id, encrypted_content, keyword_hashes, int(time.time()))
            )
            self.db_manager.execute_query(
                "INSERT INTO document_access (doc_id, user_id, session_id, encrypted_key) VALUES (%s, %s, %s, %s)",
                (doc_id, self.user_id, self.current_session_id, encrypted_key)
            )
            self.db_manager.commit()
            logger.info(f"Document {doc_id} added to session {self.current_session_id} for user {self.user_id}.")
        except Exception as e:
            self.db_manager.rollback()  # Rollback on error
            logger.error(f"Failed to add document: {e}")
            raise

    def _generate_trigrams(self, keyword: str) -> List[str]:
        """Generate trigrams from a keyword for partial matching"""
        normalized = re.sub(r'[^a-zA-Z0-9]', '', keyword.lower())
        
        trigrams = []
        if len(normalized) <= 3:
            trigrams = [normalized]
        else:
            for i in range(len(normalized) - 2):
                trigrams.append(normalized[i:i+3])
                
        return trigrams

    def add_document_with_partial_search(self, doc_id: str, content: str, keywords: List[str]):
        """Add document with partial search capability."""
        # First add the document normally
        self.add_document(doc_id, content, keywords)
        
        # Then add trigram information for each keyword
        for keyword in keywords:
            trigrams = self._generate_trigrams(keyword)
            for position, trigram in enumerate(trigrams):
                # Use current session key for trigram hashing
                h = hmac.HMAC(self.current_session_key, SHA256(), backend=default_backend())
                h.update(trigram.encode('utf-8'))
                trigram_hash = h.finalize()
                
                encrypted_position = self._encrypt_data(str(position).encode(), self.current_session_key)
                
                self.db_manager.execute_query(
                    """REPLACE INTO keyword_trigrams 
                       (doc_id, user_id, session_id, trigram_hash, encrypted_position) VALUES (%s, %s, %s, %s, %s)""",
                    (doc_id, self.user_id, self.current_session_id, trigram_hash, encrypted_position)
                )
                
        logger.info(f"Added trigram indices for document {doc_id} in session {self.current_session_id}")

    def search_documents(self, keyword: str, include_archived: bool = False) -> List[str]:
        """Search documents containing keyword."""
        matches = []
        
        # Search in current session
        if self.current_session_key:
            matches.extend(self._search_in_session(keyword, self.current_session_id, self.current_session_key))
        
        # Search in archived sessions if requested and allowed
        if include_archived and self.archive_access_key:
            archived_sessions = self.db_manager.execute_query(
                "SELECT session_id FROM sessions WHERE user_id = %s AND session_id != %s AND is_active = 0",
                (self.user_id, self.current_session_id or "")
            )
            
            for session_row in archived_sessions:
                session_id = session_row['session_id']
                session_key = self._get_session_key(session_id)
                if session_key:
                    matches.extend(self._search_in_session(keyword, session_id, session_key))
        
        return list(set(matches))  # Remove duplicates

    def _search_in_session(self, keyword: str, session_id: str, session_key: bytes) -> List[str]:
        """Search for keyword within a specific session."""
        # Generate search token using session key
        h = hmac.HMAC(session_key, SHA256(), backend=default_backend())
        h.update(keyword.encode('utf-8'))
        search_token = h.finalize()

        # Get documents in this session that the user has access to
        results = self.db_manager.execute_query(
            """SELECT d.doc_id, d.keyword_hashes FROM documents d
               JOIN document_access a ON d.doc_id = a.doc_id AND d.user_id = a.user_id
               WHERE d.session_id = %s AND a.user_id = %s""",
            (session_id, self.user_id)
        )

        matches = []
        for row in results or []:
            hashes = row['keyword_hashes']
            # Compare each 32-byte hash chunk
            for i in range(0, len(hashes), 32):
                if compare_digest(hashes[i:i+32], search_token):
                    matches.append(row['doc_id'])
                    break  # No need to check other hashes for this doc
        return matches

    def partial_search(self, partial_keyword: str, include_archived: bool = False) -> List[str]:
        """Search for documents containing partial keyword matches"""
        matches = set()
        
        # Search in current session
        if self.current_session_key:
            matches.update(self._partial_search_in_session(partial_keyword, self.current_session_id, self.current_session_key))
        
        # Search in archived sessions if requested and allowed
        if include_archived and self.archive_access_key:
            archived_sessions = self.db_manager.execute_query(
                "SELECT session_id FROM sessions WHERE user_id = %s AND session_id != %s AND is_active = 0",
                (self.user_id, self.current_session_id or "")
            )
            
            for session_row in archived_sessions:
                session_id = session_row['session_id']
                session_key = self._get_session_key(session_id)
                if session_key:
                    matches.update(self._partial_search_in_session(partial_keyword, session_id, session_key))
        
        return list(matches)

    def _partial_search_in_session(self, partial_keyword: str, session_id: str, session_key: bytes) -> List[str]:
        """Partial search within a specific session."""
        trigrams = self._generate_trigrams(partial_keyword)
        if not trigrams:
            return []
        
        potential_matches = set()
        first_search = True
        
        for trigram in trigrams:
            h = hmac.HMAC(session_key, SHA256(), backend=default_backend())
            h.update(trigram.encode('utf-8'))
            trigram_hash = h.finalize()
            
            results = self.db_manager.execute_query(
                """SELECT DISTINCT kt.doc_id 
                   FROM keyword_trigrams kt
                   JOIN document_access da ON kt.doc_id = da.doc_id AND kt.user_id = da.user_id
                   WHERE kt.session_id = %s AND kt.trigram_hash = %s AND da.user_id = %s""",
                (session_id, trigram_hash, self.user_id)
            )
            
            doc_ids = {row['doc_id'] for row in results or []}
            
            if first_search:
                potential_matches = doc_ids
                first_search = False
            else:
                potential_matches &= doc_ids
                
        return list(potential_matches)

    def get_document(self, doc_id: str) -> Optional[str]:
        """Retrieve and decrypt document (checks current session first, then archived if allowed)."""
        # First check document access and get session info
        access_info = self.db_manager.execute_query(
            "SELECT session_id, encrypted_key FROM document_access WHERE doc_id = %s AND user_id = %s",
            (doc_id, self.user_id)
        )
        
        if not access_info:
            logger.warning("No access to document.")
            return None

        session_id = access_info[0]['session_id']
        encrypted_doc_key = access_info[0]['encrypted_key']

        # Get session key
        session_key = self._get_session_key(session_id)
        if not session_key:
            logger.warning(f"Cannot access session {session_id}. Archive access may be required.")
            return None

        try:
            # Decrypt document key
            doc_key = self._decrypt_data(encrypted_doc_key, session_key)

            # Get encrypted content
            doc_data = self.db_manager.execute_query(
                "SELECT content FROM documents WHERE doc_id = %s AND user_id = %s",
                (doc_id, self.user_id)
            )
            if not doc_data:
                return None

            # Decrypt content
            content = self._decrypt_data(doc_data[0]['content'], doc_key)
            return content.decode('utf-8')
        except InvalidTag:
            logger.error("Decryption failed - possible tampering or wrong key.")
            return None

    def list_documents(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        """List documents with session information."""
        if include_archived and self.archive_access_key:
            # List all documents user has access to
            results = self.db_manager.execute_query(
                """SELECT da.doc_id, da.session_id, d.created_at, s.is_active
                   FROM document_access da
                   JOIN documents d ON da.doc_id = d.doc_id AND da.user_id = d.user_id
                   JOIN sessions s ON da.session_id = s.session_id
                   WHERE da.user_id = %s
                   ORDER BY d.created_at DESC""",
                (self.user_id,)
            )
        else:
            # List only current session documents
            results = self.db_manager.execute_query(
                """SELECT da.doc_id, da.session_id, d.created_at, s.is_active
                   FROM document_access da
                   JOIN documents d ON da.doc_id = d.doc_id AND da.user_id = d.user_id
                   JOIN sessions s ON da.session_id = s.session_id
                   WHERE da.user_id = %s AND da.session_id = %s
                   ORDER BY d.created_at DESC""",
                (self.user_id, self.current_session_id)
            )
        
        documents = []
        for row in results or []:
            doc_info = {
                'doc_id': row['doc_id'],
                'session_id': row['session_id'],
                'created_at': row['created_at'],
                'is_current_session': row['session_id'] == self.current_session_id,
                'is_active_session': bool(row['is_active'])
            }
            documents.append(doc_info)
        
        return documents

    def delete_document(self, doc_id: str):
        """Delete a document and all associated data."""
        # Check if user has access
        access = self.db_manager.execute_query(
            "SELECT doc_id, session_id FROM document_access WHERE doc_id = %s AND user_id = %s",
            (doc_id, self.user_id)
        )
        if not access:
            logger.warning(f"No access to document {doc_id}.")
            raise PermissionError(f"No access to document {doc_id}.")

        try:
            self.db_manager.start_transaction()
            # Delete trigram data
            self.db_manager.execute_query(
                "DELETE FROM keyword_trigrams WHERE doc_id = %s AND user_id = %s",
                (doc_id, self.user_id)
            )
            
            # Delete all access records
            self.db_manager.execute_query(
                "DELETE FROM document_access WHERE doc_id = %s AND user_id = %s",
                (doc_id, self.user_id)
            )
            
            # Delete the document
            self.db_manager.execute_query(
                "DELETE FROM documents WHERE doc_id = %s AND user_id = %s",
                (doc_id, self.user_id)
            )
            self.db_manager.commit() 
            logger.info(f"Document {doc_id} deleted successfully.")
        except Exception as e:
            self.db_manager.rollback() 
            logger.error(f"Failed to delete document: {e}")
            raise

    def get_session_info(self) -> Dict[str, Any]:
        """Get information about current and archived sessions."""
        sessions = self.db_manager.execute_query(
            """SELECT session_id, created_at, is_active,
                      (SELECT COUNT(*) FROM documents WHERE session_id = s.session_id AND user_id = s.user_id) as doc_count
               FROM sessions s
               WHERE user_id = %s
               ORDER BY created_at DESC""",
            (self.user_id,)
        )
        
        info = {
            'current_session_id': self.current_session_id,
            'archive_access_available': self.archive_access_key is not None,
            'sessions': []
        }
        
        for session in sessions or []:
            info['sessions'].append({
                'session_id': session['session_id'],
                'created_at': session['created_at'],
                'is_active': bool(session['is_active']),
                'document_count': session['doc_count'],
                'is_current': session['session_id'] == self.current_session_id
            })
        
        return info


def main():
    print("=== Forward Privacy Searchable Encryption System ===")
    
    server_url = input("Enter server URL (e.g., http://your-ubuntu-ip:9999): ")
    db_manager = RemoteDatabaseManager(server_url)
    
    try:
        db_manager.connect()
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        return

    user_id = input("Enter your user ID: ")
    passphrase = getpass.getpass("Enter your main passphrase: ")

    try:
        sse = ForwardPrivacySearchableEncryption(db_manager, user_id, passphrase)
        if sse.is_new_user:
            print(f"New user '{user_id}' created successfully.")
            
            # Set archive passcode for new users
            set_archive = input("Would you like to set an archive passcode for accessing old sessions? (y/n): ").strip().lower()
            if set_archive == 'y':
                archive_passcode = getpass.getpass("Enter archive passcode: ")
                confirm_passcode = getpass.getpass("Confirm archive passcode: ")
                if archive_passcode == confirm_passcode:
                    sse.set_archive_passcode(passphrase, archive_passcode)
                    print("Archive passcode set successfully!")
                else:
                    print("Passcodes don't match. Archive passcode not set.")
        else:
            print(f"Welcome back, {user_id}!")
            
            # Ask if they want to unlock archive access
            unlock_archive = input("Do you want to unlock access to archived sessions? (y/n): ").strip().lower()
            if unlock_archive == 'y':
                archive_passcode = getpass.getpass("Enter archive passcode: ")
                if sse.unlock_archive_access(archive_passcode):
                    print("Archive access unlocked! You can now access documents from previous sessions.")
                else:
                    print("Invalid archive passcode. You can only access current session documents.")
            
    except Exception as e:
        print(f"Error: {e}")
        return

    while True:
        print("\n=== Main Menu ===")
        print("1. Add Document")
        print("2. Search Documents")
        print("3. Partial Search")
        print("4. List Documents")
        print("5. View Document")
        print("6. Delete Document")
        print("7. Session Management")
        print("8. Archive Access")
        print("9. Exit")

        choice = input("Enter your choice: ")

        try:
            if choice == "1":
                doc_id = input("Enter document ID: ")
                content = input("Enter document content: ")
                keywords = input("Enter keywords (comma-separated): ").split(",")
                sse.add_document_with_partial_search(doc_id, content, [k.strip() for k in keywords])
                print(f"Document '{doc_id}' added to current session successfully.")
                
            elif choice == "2":
                keyword = input("Enter keyword to search for: ")
                include_archived = False
                if sse.archive_access_key:
                    include_archived = input("Search in archived sessions too? (y/n): ").strip().lower() == 'y'
                
                results = sse.search_documents(keyword, include_archived)
                if results:
                    print("Documents containing the keyword:")
                    for doc_id in results:
                        print(f"- {doc_id}")
                else:
                    print("No matching documents found.")
                    
            elif choice == "3":
                partial_keyword = input("Enter partial keyword to search for: ")
                include_archived = False
                if sse.archive_access_key:
                    include_archived = input("Search in archived sessions too? (y/n): ").strip().lower() == 'y'
                
                results = sse.partial_search(partial_keyword, include_archived)
                if results:
                    print("Documents containing the partial keyword match:")
                    for doc_id in results:
                        print(f"- {doc_id}")
                else:
                    print("No matching documents found.")
                    
            elif choice == "4":
                include_archived = False
                if sse.archive_access_key:
                    include_archived = input("Include archived session documents? (y/n): ").strip().lower() == 'y'
                
                documents = sse.list_documents(include_archived)
                if documents:
                    print("\nYour documents:")
                    print("-" * 80)
                    for doc in documents:
                        session_type = "CURRENT" if doc['is_current_session'] else "ARCHIVED"
                        active_status = "ACTIVE" if doc['is_active_session'] else "INACTIVE"
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(doc['created_at']))
                        print(f"ID: {doc['doc_id']}")
                        print(f"  Session: {doc['session_id'][:8]}... ({session_type}, {active_status})")
                        print(f"  Created: {timestamp}")
                        print()
                else:
                    print("No documents found.")
                    
            elif choice == "5":
                doc_id = input("Enter document ID to view: ")
                content = sse.get_document(doc_id)
                if content:
                    print(f"\nContent of '{doc_id}':")
                    print("-" * 40)
                    print(content)
                    print("-" * 40)
                else:
                    print("Document not found, access denied, or archive access required.")
                    
            elif choice == "6":
                doc_id = input("Enter document ID to delete: ")
                sse.delete_document(doc_id)
                print(f"Document '{doc_id}' deleted successfully.")
                
            elif choice == "7":
                print("\n=== Session Management ===")
                print("1. View Session Information")
                print("2. End Current Session (Start New Session)")
                print("3. Back to Main Menu")
                
                session_choice = input("Enter choice: ")
                
                if session_choice == "1":
                    info = sse.get_session_info()
                    print(f"\nCurrent Session: {info['current_session_id']}")
                    print(f"Archive Access: {'Available' if info['archive_access_available'] else 'Not Available'}")
                    print("\nAll Sessions:")
                    print("-" * 60)
                    for session in info['sessions']:
                        status = []
                        if session['is_current']:
                            status.append("CURRENT")
                        if session['is_active']:
                            status.append("ACTIVE")
                        else:
                            status.append("ARCHIVED")
                        
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['created_at']))
                        print(f"Session: {session['session_id']}")
                        print(f"  Status: {', '.join(status)}")
                        print(f"  Created: {timestamp}")
                        print(f"  Documents: {session['document_count']}")
                        print()
                        
                elif session_choice == "2":
                    confirm = input("Are you sure you want to end current session? This implements forward privacy. (y/n): ")
                    if confirm.strip().lower() == 'y':
                        old_session = sse.current_session_id
                        sse.end_current_session()
                        print(f"Session {old_session[:8]}... ended.")
                        print(f"New session {sse.current_session_id[:8]}... started.")
                        print("Forward privacy is now active - old documents require archive access.")
                        
            elif choice == "8":
                print("\n=== Archive Access Management ===")
                print("1. Set/Change Archive Passcode")
                print("2. Unlock Archive Access")
                print("3. Lock Archive Access")
                print("4. Back to Main Menu")
                
                archive_choice = input("Enter choice: ")
                
                if archive_choice == "1":
                    # Check if we need old passcode
                    result = sse.db_manager.execute_query(
                        "SELECT archive_key_hash FROM users WHERE user_id = %s",
                        (sse.user_id,)
                    )
                    has_existing = result and result[0]['archive_key_hash']
                    
                    old_passcode = None
                    if has_existing:
                        old_passcode = getpass.getpass("Enter current archive passcode: ")
                    else:
                        old_passcode = getpass.getpass("Enter your main passphrase: ")
                    
                    new_passcode = getpass.getpass("Enter new archive passcode: ")
                    confirm_passcode = getpass.getpass("Confirm new archive passcode: ")
                    
                    if new_passcode == confirm_passcode:
                        try:
                            sse.set_archive_passcode(old_passcode, new_passcode)
                            print("Archive passcode set/updated successfully!")
                        except ValueError as e:
                            print(f"Error: {e}")
                    else:
                        print("Passcodes don't match.")
                        
                elif archive_choice == "2":
                    archive_passcode = getpass.getpass("Enter archive passcode: ")
                    if sse.unlock_archive_access(archive_passcode):
                        print("Archive access unlocked!")
                    else:
                        print("Invalid archive passcode or no passcode set.")
                        
                elif archive_choice == "3":
                    sse.archive_access_key = None
                    print("Archive access locked. You can now only access current session documents.")
                    
            elif choice == "9":
                print("Exiting application...")
                break
            else:
                print("Invalid choice. Please try again.")
                
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            print("Debug info:", traceback.format_exc())

    db_manager.disconnect()


if __name__ == "__main__":
    main()