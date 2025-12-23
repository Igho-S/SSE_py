# English

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
  - `cryptography` for encryption and key derivation
  - `requests` for communicating with the database server
  - `getpass` for secure passphrase input
- **MySQL Server**: A running MySQL server accessible via a REST API.
- **Server Setup**: A corresponding server that handles database operations via endpoints.

## Installation

1. **Install Python dependencies**:

   ```bash
   pip install cryptography requests
   ```

2. **Set up the MySQL database server**:
   Already set up and running at **http://46.17.44.229:1962**

4. **Clone or download the code**:

   - Save the provided `sse23c_mysql.py` file to your project directory.
   - OR download the executable (for windows)

## Usage

1. **Run the application**:

   ```bash
   python sse23c_mysql.py
   ```

2. **Initial Setup**:

   - Enter the server URL: 

     ```markdown
     (http://46.17.44.229:1962)
     ```
   - Provide a user ID and main passphrase.
   - For new users, optionally set an archive passcode.

3. **Main Menu Options**:

   - **Add Document**: Encrypt and store a document with associated keywords for searching.
   - **Search Documents**: Search for documents containing a specific keyword (exact match).
   - **Partial Search**: Search for documents with partial keyword matches using trigrams.
   - **List Documents**: View all accessible documents, optionally including archived ones.
   - **View Document**: Retrieve and decrypt a specific document by ID.
   - **Delete Document**: Remove a document and its associated data. (backward private)
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
   - Ending a session implements forward privacy, meaning documents from that session cannot be accessed without the archive passcode. In case of not setting an archive password, any document stored in the database in that session will become unavailable
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

Contributions are welcome! 
Please submit pull requests or open issues on the project's repository (if applicable) for bug reports, feature requests, or improvements.

## 

# Russian

# Система шифрования с возможностью поиска и прямой приватностью

## Обзор

Система шифрования с возможностью поиска Forward Privacy Searchable Encryption System представляет собой безопасное приложение для управления документами, предназначенное для предоставления зашифрованного хранения и возможностей поиска с обеспечением прямой приватности. Она позволяет пользователям безопасно хранить, искать и извлекать документы с функциями вроде шифрования на основе сессий, частичного поиска по ключевым словам и контроля доступа к архиву. Система использует AES-GCM для шифрования, PBKDF2 для вывода ключей и HMAC для хэшей поисковых ключевых слов, обеспечивая надежную безопасность и приватность.

Это приложение особенно подходит для сценариев, где чувствительные данные требуют безопасного хранения и поиска, с возможностью ротации ключей шифрования (через сессии) для предотвращения доступа к старым данным после окончания сессии, реализуя прямую приватность.

## Возможности

- **Зашифрованное хранение документов**: Документы шифруются с помощью AES-GCM с использованием ключей, специфичных для документа, которые сами шифруются ключами, специфичными для сессии.
- **Шифрование с возможностью поиска**: Ключевые слова хэшируются с помощью HMAC-SHA256, позволяя безопасный поиск без расшифровки всего документа.
- **Частичный поиск по ключевым словам**: Поддерживает частичное совпадение ключевых слов на основе триграмм для гибких возможностей поиска.
- **Прямая приватность**: Реализует ротацию ключей на основе сессий, чтобы окончание сессии предотвращало доступ к документам из предыдущих сессий, если они не разблокированы явно.
- **Контроль доступа к архиву**: Предоставляет отдельный пароль архива для доступа к документам из предыдущих сессий, повышая безопасность архивных данных.
- **Интеграция с базой данных**: Использует базу данных MySQL (через удаленный сервер) для хранения зашифрованных документов, информации о сессиях и данных контроля доступа.
- **Аутентификация пользователей**: Безопасная аутентификация пользователей с ключами, выведенными из PBKDF2, и солью для каждого пользователя.
- **Управление сессиями**: Позволяет пользователям просматривать, завершать и начинать новые сессии для обеспечения прямой приватности.
- **Безопасность транзакций**: Использует транзакции базы данных для обеспечения целостности данных во время операций с документами.


## Предварительные требования

Для запуска приложения требуется:

- **Python 3.7+**
- **Необходимые библиотеки Python**:
    - `cryptography` для шифрования и вывода ключей
    - `requests` для общения с сервером базы данных
    - `getpass` для безопасного ввода пароля
- **Сервер MySQL**: Работающий сервер MySQL, доступный через REST API.
- **Настройка сервера**: Соответствующий сервер, обрабатывающий операции с базой данных через конечные точки.


## Установка

1. **Установите зависимости Python**:

```bash
pip install cryptography requests
```

2. **Настройте сервер базы данных MySQL**:
Уже настроен и запущен по адресу **http://46.17.44.229:1962**
3. **Склонируйте или скачайте код**:
    - Сохраните предоставленный файл `sse23c_mysql.py` в директорию проекта.
    - ИЛИ скачайте исполняемый файл (для Windows)

## Использование

1. **Запустите приложение**:

```bash
python sse23c_mysql.py
```

2. **Начальная настройка**:
    - Введите URL сервера:

```markdown
(http://46.17.44.229:1962)
```

    - Укажите ID пользователя и основной пароль.
    - Для новых пользователей optionally установите пароль архива.
3. **Опции главного меню**:
    - **Добавить документ**: Зашифруйте и сохраните документ с ассоциированными ключевыми словами для поиска.
    - **Поиск документов**: Поиск документов, содержащих конкретное ключевое слово (точное совпадение).
    - **Частичный поиск**: Поиск документов с частичными совпадениями ключевых слов с использованием триграмм.
    - **Список документов**: Просмотр всех доступных документов, optionally включая архивные.
    - **Просмотр документа**: Извлечение и расшифровка конкретного документа по ID.
    - **Удаление документа**: Удаление документа и связанных данных. (обратная приватность)
    - **Управление сессиями**:
        - Просмотр информации о сессиях (текущие и архивные сессии, количество документов).
        - Завершение текущей сессии для начала новой, обеспечивая прямую приватность.
    - **Доступ к архиву**:
        - Установка или изменение пароля архива.
        - Разблокировка доступа к архиву для просмотра документов из предыдущих сессий.
        - Блокировка доступа к архиву для ограничения доступа текущей сессией.
    - **Выход**: Отключение от сервера и выход из приложения.
4. **Примечания по безопасности**:
    - Убедитесь, что основной пароль и пароль архива сильные и надежно хранятся.
    - Завершение сессии реализует прямую приватность, что означает, что документы из этой сессии не могут быть доступны без пароля архива. В случае отсутствия пароля архива любой документ, сохраненный в базе данных в этой сессии, станет недоступным.
    - Пароль архива требуется для доступа к документам из предыдущих сессий.

## Схема базы данных

Приложение использует следующие таблицы MySQL:

- **users**:
    - `user_id`: Уникальный идентификатор пользователя.
    - `salt`: Случайная соль для вывода ключей.
    - `key_encryption_key`: Ключ, выведенный из PBKDF2, для шифрования ключей сессий.
    - `archive_key_hash`: Хэш пароля архива.
    - `current_session_id`: ID текущей активной сессии.
- **sessions**:
    - `session_id`: Уникальный идентификатор сессии.
    - `user_id`: Внешний ключ к пользователю.
    - `session_key_encrypted`: Ключ сессии, зашифрованный ключом шифрования пользователя или ключом архива.
    - `created_at`: Метка времени создания сессии.
    - `is_active`: Указывает, активна ли сессия (1) или архивирована (0).
- **documents**:
    - `doc_id`: Уникальный идентификатор документа.
    - `session_id`: Внешний ключ к сессии.
    - `content`: Зашифрованное содержимое документа.
    - `keyword_hashes`: Конкатенированные HMAC-хэши ключевых слов.
    - `created_at`: Метка времени создания документа.
- **document_access**:
    - `doc_id`: Внешний ключ к документу.
    - `user_id`: Внешний ключ к пользователю.
    - `session_id`: Внешний ключ к сессии.
    - `encrypted_key`: Ключ документа, зашифрованный ключом сессии.
- **keyword_trigrams**:
    - `doc_id`: Внешний ключ к документу.
    - `session_id`: Внешний ключ к сессии.
    - `trigram_hash`: HMAC-хэш триграммы ключевого слова.
    - `encrypted_position`: Зашифрованная позиция триграммы в ключевом слове.


## Соображения по безопасности

- **Шифрование**: Все чувствительные данные (содержимое документов, ключи сессий, ключи документов) шифруются с помощью AES-GCM, обеспечивая конфиденциальность и целостность.
- **Вывод ключей**: PBKDF2 с 600 000 итерациями и SHA256 используется для вывода ключей из паролей, обеспечивая сильную устойчивость к атакам грубой силы.
- **Прямая приватность**: Ротация ключей сессий гарантирует, что окончание сессии предотвращает доступ к предыдущим документам, если не предоставлен пароль архива.
- **Шифрование с возможностью поиска**: Хэши ключевых слов генерируются с помощью HMAC-SHA256 с ключами, специфичными для сессии, предотвращая утечку ключевых слов между сессиями.
- **Частичный поиск**: Поиск на основе триграмм позволяет гибкое совпадение при сохранении шифрования.
- **Обработка ошибок**: Приложение включает надежную обработку ошибок и управление транзакциями для предотвращения повреждения данных.


## Ограничения

- **Доступ к архиву**: Доступ к архивным документам требует пароля архива, который должен надежно управляться.
- **Производительность**: Частичные поиски могут быть медленнее для больших наборов данных из-за совпадений на основе триграмм.


## Вклад

Вклады приветствуются!
Пожалуйста, отправляйте pull-запросы или открывайте issues в репозитории проекта (если применимо) для отчетов об ошибках, запросов функций или улучшений.
