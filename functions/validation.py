from time import time
from pyotp import totp
from functions.database import *
from functions.encryption import *

secretCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
usernameCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
passwordCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "

def validate2FACode(code: str, secret: str):
    # Check the code is 6 characters long
    if len(code) != 6:
        return False

    # Check the code is a number
    if not code.isnumeric():
        return False
    
    # Check the secret is 32-characters long
    if len(secret) != 32:
        return False
    
    # Check all characters of the secret are in the secret character set
    if not all(character in secretCharSet for character in secret):
        return False

    # Use the 2FA secret passed to verify the code
    return totp.TOTP(secret).verify(code)

def validate2FASecret(secret: str):
    # Check if the secret is 32 characters long
    if len(secret) != 32:
        return False
    
    # Check all characters are in the 2FA secret character set
    if not all(character in secretCharSet for character in secret):
        return False
    
    # Return True if all checks pass
    return True

def validateUsername(username: str):
    # Check the username is between 3 and 20 (inclusive) characters long
    if len(username) < 3 or len(username) > 20:
        return False
    
    # Check all characters are in the username character set
    if not all(character in usernameCharSet for character in username):
        return False
    
    # Return True if all checks pass
    return True

def validatePassword(password: str, hash: str = None):
    # Check the password is between 8 and 32 (inclusive) characters long
    if len(password) < 8 or len(password) > 32:
        return False
    
    # Check all characters are in the password character set
    if not all(character in passwordCharSet for character in password):
        return False
    
    # Check the password matches the hash if one is passed, otherwise skip this check
    if hash:
        return verifyHash(hash, password)
    else:
        return True

def validateUserSessionToken(userSessionToken):
    try:
        # Decode the user session token
        id, token = readUserSessionToken(userSessionToken)

        # Get the session's information from the database and check if the session exists
        sessionInfo = getSessionInfo(id)
        if len(sessionInfo) < 1:
            return False

        hashedToken = sessionInfo[0][1]
        lastActivity = sessionInfo[0][2]
        sessionCreated = sessionInfo[0][3]
        username = sessionInfo[0][4]

        # Check if the session is over seven days old
        if time() - sessionCreated >= 604800:
            deleteSession(id)
            return False

        # Check the last activity and the user's session inactivity threshold
        userInfo = getUserInfo(username)
        sessionInactivityThreshold = userInfo[4]

        if time() - lastActivity >= sessionInactivityThreshold:
            deleteSession(id)
            return False

        # Check the token matches the stored hash
        if not verifyHash(hashedToken, token):
            return False

        # Update the last activity timestamp to the current time
        updateSessionLastActivity(id)
        
        return username
    except:
        return False

def readFile(name):
    x = open(name, "r")
    y = x.read()
    x.close()
    del x
    return y

def validateIconName(iconName):
    # Get a list of all the valid icon names
    iconNames = readFile("data/iconNames.txt").splitlines()

    # Check whether the icon name is in the list
    if iconName in iconNames:
        return True
    else:
        return False

def validatePasswordName(name):
    # Check the password name is between 3 and 20 (inclusive) characters long
    if len(name) < 3 or len(name) > 20:
        return False
    
    # Check all characters are in the password name character set
    if not all(character in usernameCharSet + " " for character in name):
        return False
    
    # Return True if all checks pass
    return True

def validateStoredPassword(password: str):
    # Check the password is between 8 and 64 (inclusive) characters long
    if len(password) < 8 or len(password) > 64:
        return False
    
    # Check all characters are in the password character set
    if not all(character in passwordCharSet for character in password):
        return False
    
    # Return True if all checks pass
    return True