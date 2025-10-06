# Forward Privacy Searchable Encryption System

## Overview

The Forward Privacy Searchable Encryption System is a secure document management application designed to provide encrypted storage and searchable capabilities while ensuring forward privacy. It allows users to store, search, and retrieve documents securely, with features like session-based encryption, partial keyword search, and archive access control. The system uses AES-GCM for encryption, PBKDF2 for key derivation, and HMAC for searchable keyword hashes, ensuring robust security and privacy.

This application is particularly suited for scenarios where sensitive data needs to be stored and searched securely, with the ability to rotate encryption keys (via sessions) to prevent access to old data after a session ends, thus implementing forward privacy.

## Features

- **Encrypted Document Storage**: Documents are encrypted using AES-GCM with document-specific keys, which are themselves encrypted with session-specific keys.
- **Searchable Encryption**: Keywords are hashed using HMAC-SHA256, allowing secure searches without decrypting the entire document.
- **Partial Keyword Search**: Supports trigram-based partial keyword matching for flexible search capabilities.
- **Forward Privacy**: Implements session-based key rotation to ensure that ending a session prevents access to documents from previous sessions unless explicitly unlocked.
- **Archive Access Control**: Provides a separate archive passcode to access documents from previous sessions, enhancing security for archived data.
- **Database Integration**: Uses a MySQL database (via a remote server) to store encrypted documents, session information, and access control data.
- **User Authentication**: Secure user authentication with PBKDF2-derived keys and salt for each user.
- **Session Management**: Allows users to view, end, and start new sessions to enforce forward privacy.
- **Transaction Safety**: Uses database transactions to ensure data integrity during document operations.

## Prerequisites

To run this application, you need:

- **Python 3.7+**
- **Required Python libraries**:
  - `cryptography` (for encryption and key derivation)
  - `requests` (for communicating with the database server)
  - `getpass` (for secure passphrase input)
- **MySQL Server**: A running MySQL server accessible via a REST API (as implemented by the server at `server_url`).
- **Server Setup**: A corresponding server (not included in this code) that handles database operations via endpoints like `/connect`, `/execute_query`, etc.
- **Network Access**: Ensure the client can reach the server URL provided during setup.

## Installation

1. **Install Python dependencies**:

   ```bash
   pip install cryptography requests
   ```

2. **Set up the MySQL database server**:

   - Ensure a MySQL server is running and accessible.
   - Set up a REST API server (e.g., using Flask or FastAPI) that exposes endpoints for database operations (`/connect`, `/execute_query`, `/start_transaction`, `/commit`, `/rollback`, `/disconnect`).
   - The server must handle MySQL queries and return results in JSON format.

3. **Clone or download the code**:

   - Save the provided `sse23c_mysql.py` file to your project directory.

## Usage

1. **Run the application**:

   ```bash
   python sse23c_mysql.py
   ```

2. **Initial Setup**:

   - Enter the server URL: 

     ```markdown
     (http://23.26.156.65:9999)
     ```
   - Provide a user ID and main passphrase.
   - For new users, optionally set an archive passcode to access documents from previous sessions.

3. **Main Menu Options**:

   - **Add Document**: Encrypt and store a document with associated keywords for searching.
   - **Search Documents**: Search for documents containing a specific keyword (exact match).
   - **Partial Search**: Search for documents with partial keyword matches using trigrams.
   - **List Documents**: View all accessible documents, optionally including archived ones.
   - **View Document**: Retrieve and decrypt a specific document by ID.
   - **Delete Document**: Remove a document and its associated data.
   - **Session Management**:
     - View session information (current and archived sessions, document counts).
     - End the current session to start a new one, enforcing forward privacy.
   - **Archive Access**:
     - Set or change the archive passcode.
     - Unlock archive access to view documents from previous sessions.
     - Lock archive access to restrict access to the current session.
   - **Exit**: Disconnect from the server and exit the application.

4. **Security Notes**:

   - Ensure the main passphrase and archive passcode are strong and securely stored.
   - Ending a session implements forward privacy, meaning documents from that session cannot be accessed without the archive passcode.
   - The archive passcode is required to access documents from previous sessions.

## Database Schema

The application uses the following MySQL tables:

- **users**:

  - `user_id`: Unique identifier for the user.
  - `salt`: Random salt for key derivation.
  - `key_encryption_key`: PBKDF2-derived key for encrypting session keys.
  - `archive_key_hash`: Hash of the archive passcode.
  - `current_session_id`: ID of the current active session.

- **sessions**:

  - `session_id`: Unique identifier for a session.
  - `user_id`: Foreign key to the user.
  - `session_key_encrypted`: Session key encrypted with the user's key_encryption_key or archive key.
  - `created_at`: Timestamp of session creation.
  - `is_active`: Indicates if the session is active (1) or archived (0).

- **documents**:

  - `doc_id`: Unique identifier for a document.
  - `session_id`: Foreign key to the session.
  - `content`: Encrypted document content.
  - `keyword_hashes`: Concatenated HMAC hashes of keywords.
  - `created_at`: Timestamp of document creation.

- **document_access**:

  - `doc_id`: Foreign key to the document.
  - `user_id`: Foreign key to the user.
  - `session_id`: Foreign key to the session.
  - `encrypted_key`: Document key encrypted with the session key.

- **keyword_trigrams**:

  - `doc_id`: Foreign key to the document.
  - `session_id`: Foreign key to the session.
  - `trigram_hash`: HMAC hash of a keyword trigram.
  - `encrypted_position`: Encrypted position of the trigram in the keyword.

## Security Considerations

- **Encryption**: All sensitive data (document content, session keys, document keys) is encrypted using AES-GCM, which provides confidentiality and integrity.
- **Key Derivation**: PBKDF2 with 600,000 iterations and SHA256 is used to derive keys from passphrases, providing strong resistance to brute-force attacks.
- **Forward Privacy**: Session key rotation ensures that ending a session prevents access to previous documents unless the archive passcode is provided.
- **Searchable Encryption**: Keyword hashes are generated using HMAC-SHA256 with session-specific keys, preventing keyword leakage across sessions.
- **Partial Search**: Trigram-based search enables flexible matching while maintaining encryption.
- **Error Handling**: The application includes robust error handling and transaction management to prevent data corruption.

## Limitations

- **Archive Access**: Accessing archived documents requires the archive passcode, which must be securely managed.
- **Performance**: Partial searches may be slower for large datasets due to trigram-based matching.

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the project's repository (if applicable) for bug reports, feature requests, or improvements.

## 

---

# Система шифрования с возможностью поиска и прямой приватностью

## Обзор

Система шифрования с возможностью поиска и прямой приватностью — это безопасное приложение для управления документами, обеспечивающее зашифрованное хранение и поиск с поддержкой прямой приватности. Оно позволяет пользователям безопасно хранить, искать и извлекать документы с использованием таких функций, как шифрование на основе сессий, частичный поиск по ключевым словам и контроль доступа к архивам. Система использует AES-GCM для шифрования, PBKDF2 для генерации ключей и HMAC для создания хэшей ключевых слов, обеспечивая надежную безопасность и конфиденциальность.

Это приложение особенно подходит для сценариев, где необходимо безопасно хранить и искать конфиденциальные данные, с возможностью ротации ключей шифрования (через сессии), чтобы предотвратить доступ к старым данным после завершения сессии, реализуя прямую приватность.

## Особенности

- **Зашифрованное хранение документов**: Документы шифруются с помощью AES-GCM с использованием уникальных ключей для каждого документа, которые, в свою очередь, шифруются с помощью сессионных ключей.
- **Шифрование с возможностью поиска**: Ключевые слова хэшируются с использованием HMAC-SHA256, что позволяет выполнять безопасный поиск без расшифровки всего документа.
- **Частичный поиск по ключевым словам**: Поддержка поиска на основе триграмм для гибкого соответствия.
- **Прямая приватность**: Реализация ротации ключей на основе сессий гарантирует, что завершение сессии предотвращает доступ к документам из предыдущих сессий без явной разблокировки.
- **Контроль доступа к архивам**: Отдельный пароль для доступа к архивам обеспечивает дополнительную безопасность для архивных данных.
- **Интеграция с базой данных**: Используется база данных MySQL (через удаленный сервер) для хранения зашифрованных документов, информации о сессиях и данных контроля доступа.
- **Аутентификация пользователей**: Безопасная аутентификация пользователей с использованием ключей, сгенерированных с помощью PBKDF2, и соли для каждого пользователя.
- **Управление сессиями**: Позволяет пользователям просматривать, завершать и начинать новые сессии для обеспечения прямой приватности.
- **Безопасность транзакций**: Используются транзакции базы данных для обеспечения целостности данных во время операций с документами.

## Требования

Для работы приложения необходимы:

- **Python 3.7+**
- **Необходимые библиотеки Python**:
  - `cryptography` (для шифрования и генерации ключей)
  - `requests` (для взаимодействия с сервером базы данных)
  - `getpass` (для безопасного ввода паролей)
- **Сервер MySQL**: Запущенный сервер MySQL, доступный через REST API (реализованный на сервере по адресу `server_url`).
- **Настройка сервера**: Соответствующий сервер (не включен в этот код), который обрабатывает операции с базой данных через конечные точки, такие как `/connect`, `/execute_query` и т.д.
- **Сетевой доступ**: Убедитесь, что клиент может связаться с сервером по указанному URL.

## Установка

1. **Установите зависимости Python**:

   ```bash
   pip install cryptography requests
   ```

2. **Настройте сервер базы данных MySQL**:

   - Убедитесь, что сервер MySQL запущен и доступен.
   - Настройте сервер REST API (например, с использованием Flask или FastAPI), который предоставляет конечные точки для операций с базой данных (`/connect`, `/execute_query`, `/start_transaction`, `/commit`, `/rollback`, `/disconnect`).
   - Сервер должен обрабатывать запросы MySQL и возвращать результаты в формате JSON.

3. **Склонируйте или загрузите код**:

   - Сохраните предоставленный файл `sse23c_mysql.py` в директорию вашего проекта.

## Использование

1. **Запустите приложение**:

   ```bash
   python sse23c_mysql.py
   ```

2. **Начальная настройка**:

   - Введите URL сервера 

     ```markdown
     (http://23.26.156.65:9999)
     ```
   - Укажите идентификатор пользователя и основной пароль.
   - Для новых пользователей можно дополнительно установить пароль для доступа к архивам, чтобы получить доступ к документам из предыдущих сессий.

3. **Опции главного меню**:

   - **Добавить документ**: Зашифровать и сохранить документ с соответствующими ключевыми словами для поиска.
   - **Поиск документов**: Поиск документов, содержащих определенное ключевое слово (точное совпадение).
   - **Частичный поиск**: Поиск документов с частичным совпадением ключевых слов с использованием триграмм.
   - **Список документов**: Просмотр всех доступных документов, с возможностью включения архивных.
   - **Просмотр документа**: Извлечение и расшифровка определенного документа по идентификатору.
   - **Удаление документа**: Удаление документа и связанных с ним данных.
   - **Управление сессиями**:
     - Просмотр информации о сессиях (текущая и архивные сессии, количество документов).
     - Завершение текущей сессии и начало новой для обеспечения прямой приватности.
   - **Доступ к архивам**:
     - Установка или изменение пароля для доступа к архивам.
     - Разблокировка доступа к архивам для просмотра документов из предыдущих сессий.
     - Блокировка доступа к архивам для ограничения доступа только к текущей сессии.
   - **Выход**: Отключение от сервера и завершение работы приложения.

4. **Заметки по безопасности**:

   - Убедитесь, что основной пароль и пароль для доступа к архивам надежны и хранятся безопасно.
   - Завершение сессии реализует прямую приватность, что означает, что документы из этой сессии недоступны без пароля для архива.
   - Для доступа к документам из предыдущих сессий требуется пароль для архива.

## Схема базы данных

Приложение использует следующие таблицы MySQL:

- **users**:

  - `user_id`: Уникальный идентификатор пользователя.
  - `salt`: Случайная соль для генерации ключей.
  - `key_encryption_key`: Ключ, сгенерированный с помощью PBKDF2, для шифрования сессионных ключей.
  - `archive_key_hash`: Хэш пароля для доступа к архивам.
  - `current_session_id`: Идентификатор текущей активной сессии.

- **sessions**:

  - `session_id`: Уникальный идентификатор сессии.
  - `user_id`: Внешний ключ на пользователя.
  - `session_key_encrypted`: Сессионный ключ, зашифрованный с помощью `key_encryption_key` или ключа архива.
  - `created_at`: Временная метка создания сессии.
  - `is_active`: Указывает, активна ли сессия (1) или заархивирована (0).

- **documents**:

  - `doc_id`: Уникальный идентификатор документа.
  - `session_id`: Внешний ключ на сессию.
  - `content`: Зашифрованное содержимое документа.
  - `keyword_hashes`: Конкатенированные HMAC-хэши ключевых слов.
  - `created_at`: Временная метка создания документа.

- **document_access**:

  - `doc_id`: Внешний ключ на документ.
  - `user_id`: Внешний ключ на пользователя.
  - `session_id`: Внешний ключ на сессию.
  - `encrypted_key`: Ключ документа, зашифрованный с помощью сессионного ключа.

- **keyword_trigrams**:

  - `doc_id`: Внешний ключ на документ.
  - `session_id`: Внешний ключ на сессию.
  - `trigram_hash`: HMAC-хэш триграммы ключевого слова.
  - `encrypted_position`: Зашифрованная позиция триграммы в ключевом слове.

## Соображения безопасности

- **Шифрование**: Все конфиденциальные данные (содержимое документов, сессионные ключи, ключи документов) шифруются с использованием AES-GCM, что обеспечивает конфиденциальность и целостность.
- **Генерация ключей**: PBKDF2 с 600 000 итераций и SHA256 используется для генерации ключей из паролей, обеспечивая высокую устойчивость к атакам перебора.
- **Прямая приватность**: Ротация сессионных ключей гарантирует, что завершение сессии предотвращает доступ к предыдущим документам без пароля для архива.
- **Шифрование с возможностью поиска**: Хэши ключевых слов генерируются с использованием HMAC-SHA256 с сессионными ключами, предотвращая утечку ключевых слов между сессиями.
- **Частичный поиск**: Поиск на основе триграмм обеспечивает гибкое соответствие при сохранении шифрования.
- **Обработка ошибок**: Приложение включает надежную обработку ошибок и управление транзакциями для предотвращения повреждения данных.

## Ограничения

- **Доступ к архивам**: Для доступа к архивным документам требуется пароль для архива, который должен быть безопасно сохранен.
- **Производительность**: Частичный поиск может быть медленнее для больших наборов данных из-за соответствия на основе триграмм.

## Вклад в проект

Приветствуются любые вклады! Пожалуйста, отправляйте запросы на включение или открывайте вопросы в репозитории проекта (если применимо) для сообщений об ошибках, запросов новых функций или улучшений.