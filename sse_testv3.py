import sqlite3
import base64
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from os import urandom

class SecureSearchableEncryption:
    def __init__(self, db_path, passphrase):
        self.db_path = db_path
        self.salt = self._get_or_create_salt()
        self.key = self._derive_key(passphrase, self.salt)
        self._initialize_db()

    def _get_or_create_salt(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT UNIQUE NOT NULL,
                value BLOB NOT NULL
            )
        """)
        cursor.execute("SELECT value FROM settings WHERE key = 'salt'")
        row = cursor.fetchone()

        if row is None:
            salt = urandom(16)
            cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("salt", salt))
            conn.commit()
        else:
            salt = row[0]

        conn.close()
        return salt

    def _derive_key(self, passphrase, salt):
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend(),
        )
        return kdf.derive(passphrase.encode())

    def _initialize_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id TEXT UNIQUE NOT NULL,
                content BLOB NOT NULL,
                keywords BLOB NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _encrypt(self, plaintext):
        iv = urandom(12)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_content = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv, encrypted_content, encryptor.tag

    def _decrypt(self, iv, encrypted_content, tag):
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_content) + decryptor.finalize()

    def _hash_keywords(self, keywords):
        keyword_hashes = []
        for keyword in keywords:
            h = hmac.HMAC(self.key, SHA256(), backend=default_backend())
            h.update(keyword.encode())
            keyword_hashes.append(h.finalize())
        return keyword_hashes

    def add_document(self, doc_id, content, keywords):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM documents WHERE doc_id = ?", (doc_id,))
        if cursor.fetchone()[0] > 0:
            print(f"Document with ID '{doc_id}' already exists. Skipping insertion.")
            conn.close()
            return

        iv, encrypted_content, tag = self._encrypt(content)
        hashed_keywords = self._hash_keywords(keywords)

        cursor.execute("""
            INSERT INTO documents (doc_id, content, keywords)
            VALUES (?, ?, ?)
        """, (
            doc_id,
            base64.b64encode(iv + tag + encrypted_content),
            base64.b64encode(b"".join(hashed_keywords)),
        ))
        conn.commit()
        conn.close()
        print(f"Document {doc_id} added successfully.")

    def search_document(self, keyword):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT doc_id, content, keywords FROM documents")
        results = cursor.fetchall()
        conn.close()

        h = hmac.HMAC(self.key, SHA256(), backend=default_backend())
        h.update(keyword.encode())
        keyword_hash = h.finalize()

        matching_documents = []
        for doc_id, content, stored_keywords in results:
            stored_keyword_hashes = base64.b64decode(stored_keywords)
            if keyword_hash in [stored_keyword_hashes[i : i + 32] for i in range(0, len(stored_keyword_hashes), 32)]:
                matching_documents.append(doc_id)

        return matching_documents

    def delete_document(self, doc_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents WHERE doc_id = ?", (doc_id,))
        if cursor.rowcount > 0:
            print(f"Document {doc_id} deleted successfully.")
        else:
            print(f"No document found with ID '{doc_id}'.")
        conn.commit()
        conn.close()

    def list_documents(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT doc_id FROM documents")
        doc_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        return doc_ids

    def view_document(self, doc_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT content FROM documents WHERE doc_id = ?", (doc_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            print(f"No document found with ID '{doc_id}'.")
            return None

        decoded_data = base64.b64decode(row[0])
        iv = decoded_data[:12]
        tag = decoded_data[12:28]
        encrypted_content = decoded_data[28:]

        try:
            content = self._decrypt(iv, encrypted_content, tag).decode()
            print("Decrypted Content:", content)
            return content
        except Exception as e:
            print("Failed to decrypt the document:", e)
            return None

    def view_document2(self, doc_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT content FROM documents WHERE doc_id = ?", (doc_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise ValueError(f"No document found with ID '{doc_id}'")

        try:
            encrypted_data = base64.b64decode(row[0])
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            encrypted_content = encrypted_data[28:]
            decrypted_content = self._decrypt(iv, encrypted_content, tag)
            return decrypted_content.decode('utf-8')
        except Exception as e:
            raise ValueError("Failed to decrypt the content. Possibly wrong passphrase") from e

def main():
    db_path = "sse_secure.db"
    passphrase = getpass.getpass("Enter a secure passphrase: ")

    sse_db = SecureSearchableEncryption(db_path, passphrase)

    while True:
        print("\nMenu:")
        print("1. Add Document")
        print("2. Search Document")
        print("3. Delete Document")
        print("4. List Documents")
        print("5. View Document")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            doc_id = input("Enter document ID: ")
            content = input("Enter document content: ")
            keywords = input("Enter keywords (comma-separated): ").split(",")
            sse_db.add_document(doc_id, content, [k.strip() for k in keywords])
        elif choice == "2":
            keyword = input("Enter keyword to search for: ")
            results = sse_db.search_document(keyword)
            if results:
                print("Documents containing the keyword:")
                for doc_id in results:
                    print(f"- {doc_id}")
            else:
                print("No matching documents found.")
        elif choice == "3":
            doc_id = input("Enter document ID to delete: ")
            sse_db.delete_document(doc_id)
        elif choice == "4":
            doc_ids = sse_db.list_documents()
            if doc_ids:
                print("Document IDs:")
                for doc_id in doc_ids:
                    print(f"- {doc_id}")
            else:
                print("No documents found.")
        elif choice == "5":
            doc_id = input("Enter document ID to view: ")
            try:
                content = sse_db.view_document2(doc_id)
                print(f"Content of '{doc_id}':\n{content}")
            except ValueError as e:
                print(e)
        elif choice == "6":
            print("Exiting application.....")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
