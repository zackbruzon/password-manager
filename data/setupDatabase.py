import sqlite3

db = sqlite3.connect("data.db")

db.execute('''
    CREATE TABLE users (
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        publicKey TEXT NOT NULL,
        privateKey TEXT NOT NULL,
        sessionInactivityThreshold INTEGER NOT NULL,
        twoFactorAuthenticationEnabled INTEGER NOT NULL,
        twoFactorAuthenticationSecret TEXT
    )
''')

db.execute('''
    CREATE TABLE sessions (
        sessionId TEXT NOT NULL UNIQUE,
        sessionToken TEXT NOT NULL,
        lastActivity INTEGER NOT NULL,
        sessionCreated INTEGER NOT NULL,
        username TEXT NOT NULL,
        privateKey TEXT NOT NULL
    )
''')

db.execute('''
    CREATE TABLE passwords (
        passwordId INTEGER NOT NULL UNIQUE,
        username TEXT NOT NULL,
        name TEXT NOT NULL,
        icon TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

db.commit()