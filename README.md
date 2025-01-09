# Sqlite Parser

Just playing around with sqlite. I wrote a parser from scratch that traverses
the table/index btrees in a sqlite database file to find a specific record.

## Usage

Clone the repo and run `python3 parse_table.py`. It'll run the equivalent of these 2 sql queries against the included `example.db` file:
```sql
SELECT * FROM users WHERE rowid = 450;
SELECT * FROM users WHERE email = 'user_450@example.com';
```

except that instead of using the stdlib sqlite3 module, it reads bytes out of a file and parses them.

The example.db file is a simple database with only one table:
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```
which is populated with 1k test user records. Note that the `UNIQUE` constraints each cause an index to be created, which
the script uses for efficient querying.