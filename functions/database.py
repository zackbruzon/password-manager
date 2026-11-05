import sqlite3
from time import time
from uuid import uuid4
from functions.encryption import *

def createUser(username: str, password: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Generate the keypair for the account
    publicKey, privateKey = generateKeypair()

    # Encrypt it to be stored in the users table
    privateKeyEncrypted = encryptAES(password, privateKey)

    # Change new line characters so SQL will see it as \n instead of an actual new line which could mess up the query
    # as RSA keys in PEM form always have new line characters in them
    #publicKeyEncoded = publicKey.replace("\n", "\\n")
    #privateKeyEncoded = privateKeyEncrypted.replace("\n", "\\n")

    # Hash the password
    passwordHashed = hash(password)

    # Add the user to the users table
    db.execute(f'''
        INSERT INTO users
        (username, password, publicKey, privateKey, sessionInactivityThreshold, twoFactorAuthenticationEnabled)
        VALUES ("{username}", "{passwordHashed}", "{publicKey}", "{privateKeyEncrypted}", 3600, 0)
    ''')
    db.commit()
    db.close()

    return createSession(username, password)

def createSession(username: str, password: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Create a random two UUID4 strings which will be the session token and ID
    # UUID4 strings are always 32 characters long so they can be used as AES keys as well
    sessionId = uuid4().hex
    sessionToken = uuid4().hex

    # Hash the session token to be stored in the sessions table
    sessionTokenHashed = hash(sessionToken)

    # Timestamp for last activity and when the session was created
    timestamp = str(int(time()))

    # Gets the decrypted private key for the user and encrypts it with the session token
    privateKey = getPrivateKey(username, password)
    privateKeyEncrypted = encryptAES(sessionToken, privateKey)

    # Adds the session to the sessions table
    db.execute(f'''
        INSERT INTO sessions
        (sessionId, sessionToken, lastActivity, sessionCreated, username, privateKey)
        VALUES ("{sessionId}", "{sessionTokenHashed}", {timestamp}, {timestamp}, "{username.lower()}", "{privateKeyEncrypted}")
    ''')
    db.commit()
    db.close()

    return makeUserSessionToken(sessionId, sessionToken)

def updateSessionLastActivity(id: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Get timestamp of the current time
    timestamp = str(int(time()))

    # Update the last activity field
    db.execute(f'''
        UPDATE sessions
        SET lastActivity = {timestamp}
        WHERE sessionId == "{id}"
    ''')
    db.commit()
    db.close()

def getUserInfo(username: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Gets all fields from the users table for the given username
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT *
        FROM users
        WHERE username == "{username.lower()}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Returns all fields for the user as a tuple
    return selection[0]

def getPasswordHash(username: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Gets the hashed password from the users table for the given username
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT password
        FROM users
        WHERE username == "{username.lower()}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Returns the hashed password where selection[0][0] is the hashed password
    return selection[0][0]

def getPrivateKey(username: str, password: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Get the private key from the users table for the given username
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT privateKey
        FROM users
        WHERE username == "{username.lower()}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Decrypt and return the private key where selection[0][0] is the encrypted private key
    return decryptAES(password, selection[0][0])

def getPrivateKeyFromSession(userSessionToken: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Get the identifier and token of the session
    id, token = readUserSessionToken(userSessionToken)

    # Get the encrypted private key for the user's session
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT privateKey
        FROM sessions
        WHERE sessionId == "{id}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Decrypt and return the private key where selection[0][0] is the encrypted private key
    return decryptAES(token, selection[0][0])

def getPublicKey(username: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Get the user's public key from the users table
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT publicKey
        FROM users
        WHERE username == "{username.lower()}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Return the public key
    return selection[0][0]

def updatePassword(username: str, oldPassword: str, newPassword: str):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Re-encrypt the user's private key with the new password
    decryptedPrivateKey = getPrivateKey(username, oldPassword)
    encryptedPrivateKey = encryptAES(newPassword, decryptedPrivateKey)

    # Hash the new password to be stored
    newPasswordHashed = hash(newPassword)

    # Save the changes to the database
    db.execute(f'''
        UPDATE users
        SET password = "{newPasswordHashed}", privateKey = "{encryptedPrivateKey}"
        WHERE username == "{username}"
    ''')
    db.commit()
    db.close()

def getSessionInfo(id):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Get the session's info from the sessions table
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT *
        FROM sessions
        WHERE sessionId == "{id}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Return the result from the query
    return selection

def deleteSession(id):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Delete the session from the sessions table
    db.execute(f'''
        DELETE
        FROM sessions
        WHERE sessionId == "{id}"
    ''')
    db.commit()
    db.close()

def deleteUsersSessions(username):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Delete the user's sessions from the sessions table
    db.execute(f'''
        DELETE
        FROM sessions
        WHERE username == "{username}"
    ''')
    db.commit()
    db.close()

def enable2FA(username, secret):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Set the user's 2FA secret to the one given and enable 2FA
    db.execute(f'''
        UPDATE users
        SET twoFactorAuthenticationSecret = "{secret}"
        WHERE username == "{username}"
    ''')
    db.commit()
    db.close()

def disable2FA(username):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Delete the user's 2FA secret and disable 2FA
    db.execute(f'''
        UPDATE users
        SET twoFactorAuthenticationSecret = NULL
        WHERE username == "{username}"
    ''')
    db.commit()
    db.close()

def createPassword(username, name, icon, password):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Generate a UUID4 string which will act as the password's identifier
    passwordId = uuid4().hex

    # Encrypt the password to be added to the database
    publicKey = getPublicKey(username)
    encryptedPassword = encryptRSA(publicKey, password)
    encryptedName = encryptRSA(publicKey, name)
    encryptedIcon = encryptRSA(publicKey, icon)

    # Add the password to the passwords table
    db.execute(f'''
        INSERT INTO passwords
        (passwordId, username, name, icon, password)
        VALUES ("{passwordId}", "{username.lower()}", "{encryptedName}", "{encryptedIcon}", "{encryptedPassword}")
    ''')
    db.commit()
    db.close()

    return passwordId

def updatePasswordName(passwordId, name, username):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Encrypt the password to be added to the database
    publicKey = getPublicKey(username)
    encryptedName = encryptRSA(publicKey, name)

    # Update the password's name
    db.execute(f'''
        UPDATE passwords
        SET name = "{encryptedName}"
        WHERE passwordId == "{passwordId}"
    ''')
    db.commit()
    db.close()

def updatePasswordIcon(passwordId, icon, username):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Encrypt the password to be added to the database
    publicKey = getPublicKey(username)
    encryptedIcon = encryptRSA(publicKey, icon)

    # Update the password's icon
    db.execute(f'''
        UPDATE passwords
        SET icon = "{encryptedIcon}"
        WHERE passwordId == "{passwordId}"
    ''')
    db.commit()
    db.close()

def updatePasswordPassword(passwordId, password, username):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Encrypt the password to be added to the database
    publicKey = getPublicKey(username)
    encryptedPassword = encryptRSA(publicKey, password)

    # Update the password's password
    db.execute(f'''
        UPDATE passwords
        SET password = "{encryptedPassword}"
        WHERE passwordId == "{passwordId}"
    ''')
    db.commit()
    db.close()

def deletePassword(passwordId):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Delete the password
    db.execute(f'''
        DELETE
        FROM passwords
        WHERE passwordId == "{passwordId}"
    ''')
    db.commit()
    db.close()

def getUsersPasswords(username, userSessionToken):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")
    
    # Get the passwords from the passwords table
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT passwordId, name, icon
        FROM passwords
        WHERE username == "{username}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Get the user's private key
    privateKey = getPrivateKeyFromSession(userSessionToken)

    # Decrypt all password and icon names and return the result
    return [
        [
            password[0],
            decryptRSA(privateKey, password[1]),
            decryptRSA(privateKey, password[2])
        ]
        for password in selection
    ]

def getPasswordInfo(passwordId, userSessionToken):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")
    
    # Get the passwords from the passwords table
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT name, icon, password
        FROM passwords
        WHERE passwordId == "{passwordId}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Get the user's private key
    privateKey = getPrivateKeyFromSession(userSessionToken)

    # Decrypt the password and return the result from the query
    return [
        decryptRSA(privateKey, selection[0][0]),
        decryptRSA(privateKey, selection[0][1]),
        decryptRSA(privateKey, selection[0][2])
    ]

def getPasswordCreator(passwordId):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")
    
    # Get the username from the passwords table
    cursor = db.cursor()
    cursor.execute(f'''
        SELECT username
        FROM passwords
        WHERE passwordId == "{passwordId}"
    ''')

    selection = cursor.fetchall()
    cursor.close()
    db.close()

    # Return the username
    return selection[0][0]

def setSessionInactivityThreshold(username: str, sessionInactivityThreshold: int):
    # Connect to the database and set a timeout in case the database is locked
    db = sqlite3.connect("data/data.db")
    db.execute("PRAGMA busy_timeout = 5000")

    # Update the session inactivity threshold field
    db.execute(f'''
        UPDATE users
        SET sessionInactivityThreshold = {sessionInactivityThreshold}
        WHERE username == "{username}"
    ''')
    db.commit()
    db.close()