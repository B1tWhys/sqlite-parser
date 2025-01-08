import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect("example.db")
cursor = conn.cursor()

# Create the users table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# Insert 1000 test users
users_to_insert = []
for i in range(1, 1001):
    username = f"user_{i}"
    email = f"user_{i}@example.com"
    password = f"password_{i}"  # Predictable test value for password
    users_to_insert.append((username, email, password))

# Use executemany for batch insertion
cursor.executemany("""
INSERT INTO users (username, email, password_hash)
VALUES (?, ?, ?)
""", users_to_insert)

# Commit changes and close connection
conn.commit()
conn.close()

