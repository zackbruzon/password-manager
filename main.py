import flask
import requests
from functions.database import *
from functions.validation import *
from functions.encryption import *
from werkzeug.serving import run_simple

app = flask.Flask("")

# Constants

hCaptchaSecret = ""
hCaptchaSiteKey = ""

# Functions

def checkCaptcha(captchaToken, ipAddress):
    # Request instructions are found in hCaptcha's documentation
    r = requests.post(
        f"https://api.hcaptcha.com/siteverify",
        data = {
            "secret": hCaptchaSecret,
            "response": captchaToken,
            "remoteip": ipAddress,
            "sitekey": hCaptchaSiteKey
        }
    )

    return r.json()["success"]

def readFile(name):
    x = open(name, "r")
    y = x.read()
    x.close()
    return y

# Backend

# Endpoint for setting the session inactivity threshold
@app.route("/api/setSessionInactivityThreshold", methods = ["POST"])
def setSessionInactivityThresholdApi():
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response
        
        if type(request["sessionInactivityThreshold"]) != int:
            return {
                "success": False,
                "error": "Invalid session inactivity threshold."
            }, 400

        if 30 <= request["sessionInactivityThreshold"] <= 86400:
            setSessionInactivityThreshold(username, request["sessionInactivityThreshold"])

            return {
                "success": True
            }
        else:
            return {
                "success": False,
                "error": "Invalid session inactivity threshold."
            }, 400
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for editing a password
@app.route("/api/editPassword/<id>", methods = ["POST"])
def editPassword(id):
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response

        # Return an error if the user didn't make the password they're trying to edit
        # This will also return an error if the password doesn't exist
        try:
            if getPasswordCreator(id) != username:
                return {
                    "success": False,
                    "error": "You didn't make this password."
                }, 403
        except:
            return {
                "success": False,
                "error": "Invalid password identifier."
            }, 404
        
        # Validate inputs and update the password depending on what the user changed
        if "name" in request:
            if not validatePasswordName(request["name"]):
                return {
                    "success": False,
                    "error": "Invalid password name."
                }, 400
            updatePasswordName(id, request["name"], username)
        
        if "icon" in request:
            if not validateIconName(request["icon"]):
                return {
                    "success": False,
                    "error": "Invalid icon."
                }, 400
            updatePasswordIcon(id, request["icon"], username)

        if "password" in request:
            if not validateStoredPassword(request["password"]):
                return {
                    "success": False,
                    "error": "Invalid password."
                }, 400
            updatePasswordPassword(id, request["password"], username)

        # Return that it was successful
        return {
            "success": True
        }
    except Exception as e:
        print(e)
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for deleting a password
@app.route("/api/deletePassword/<id>")
def deletePasswordApi(id):
    try:
        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response
        
        # Return an error if the user didn't make the password they're trying to edit
        # This will also return an error if the password doesn't exist
        try:
            if getPasswordCreator(id) != username:
                return {
                    "success": False,
                    "error": "You didn't make this password."
                }, 403
        except:
            return {
                "success": False,
                "error": "Invalid password identifier."
            }, 404

        # Delete the password    
        deletePassword(id)

        # Return that it was successful
        return {
            "success": True
        }
    except Exception as e:
        print(e)
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for getting a password's info
@app.route("/api/getPasswordInfo/<id>")
def getPasswordInfoApi(id):
    try:
        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response
        
        # Get the password's info and return it
        info = getPasswordInfo(id, flask.request.cookies.get("authentication"))

        return {
            "success": True,
            "info": {
                "name": info[0],
                "icon": info[1],
                "password": info[2]
            }
        }
    except Exception as e:
        print(e)
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for getting a user's passwords
@app.route("/api/getPasswords")
def getPasswords():
    try:
        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response
        
        # Use the database function to get the user's passwords
        passwords = getUsersPasswords(username, flask.request.cookies.get("authentication"))

        return {
            "success": True,
            "passwords": [
                {
                    "id": i[0],
                    "name": i[1],
                    "icon": i[2]
                }
                for i in passwords
            ]
        }
    except Exception as e:
        print(e)
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for creating a password
@app.route("/api/createPassword", methods = ["POST"])
def createPasswordApi():
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response
        
        # Validate the password's name
        if not validatePasswordName(request["name"]):
            return {
                "success": False,
                "error": "Invalid password name."
            }, 400
        
        # Validate the password's icon
        if request["icon"] != "none" and not validateIconName(request["icon"]):
            return {
                "success": False,
                "error": "Invalid icon."
            }, 400
        
        # Validate the password
        if not validateStoredPassword(request["password"]):
            return {
                "success": False,
                "error": "Invalid password."
            }, 400

        # Save the password
        id = createPassword(username, request["name"], request["icon"], request["password"])

        # Return the identifier so the user can be redirected to the password's page
        return {
            "success": True,
            "id": id
        }
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for logging out
@app.route("/api/logOut")
def logOut():
    try:
        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": True
                }
            )

            response.delete_cookie("authentication")

            return response

        # Get the session identifier from the user session token and delete the session
        id, _ = readUserSessionToken(flask.request.cookies.get("authentication"))
        deleteSession(id)

        response = flask.make_response(
            {
                "success": True
            }
        )

        response.delete_cookie("authentication")

        return response
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for checking whether 2FA is enabled
@app.route("/api/check2FA")
def check2FA():
    try:
        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response

        # Check whether the user has a 2FA secret stored
        userInfo = getUserInfo(username)
        twoFactorAuthenticationSecret = userInfo[6]

        if twoFactorAuthenticationSecret:
            return {
                "success": True,
                "enabled": True
            }
        else:
            return {
                "success": True,
                "enabled": False
            }
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for enabling 2FA
@app.route("/api/enable2FA", methods = ["POST"])
def enable2FAApi():
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response
        
        # Validate the 2FA secret
        if not validate2FASecret(request["secret"]):
            return {
                "success": False,
                "error": "Invalid secret."
            }, 400

        # Validate the 2FA code with the given secret
        if not validate2FACode(request["code"], request["secret"]):
            return {
                "success": False,
                "error": "Incorrect code."
            }, 400

        # Enable 2FA for the user
        enable2FA(username, request["secret"])

        return {
            "success": True
        }
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for disabling 2FA
@app.route("/api/disable2FA", methods = ["POST"])
def disable2FAApi():
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response

        # Get the user's 2FA secret        
        userInfo = getUserInfo(username)
        twoFactorAuthenticationSecret = userInfo[6]

        # Validate the code with the user's secret
        if not validate2FACode(request["code"], twoFactorAuthenticationSecret):
            return {
                "success": False,
                "error": "Incorrect code."
            }, 400

        # Disable 2FA for the user
        disable2FA(username)

        return {
            "success": True
        }
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500
    
# Endpoint for changing a user's password
@app.route("/api/changePassword", methods = ["POST"])
def changePassword():
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Validate the user session token
        if not flask.request.cookies.get("authentication"):
            return {
                "success": False,
                "error": "Unauthorised."
            }, 401

        username = validateUserSessionToken(flask.request.cookies.get("authentication"))

        if not username:
            response = flask.make_response(
                {
                    "success": False,
                    "error": "Unauthorised."
                }
            )

            response.status_code = 401
            response.delete_cookie("authentication")

            return response

        # Validate the old password
        passwordHash = getPasswordHash(username)
        if not verifyHash(passwordHash, request["oldPassword"]):
            return {
                "success": False,
                "error": "Incorrect password."
            }, 400

        # Validate the new password
        if not validatePassword(request["newPassword"]):
            return {
                "success": False,
                "error": "Password doesn't meet the requirements."
            }, 400

        updatePassword(username, request["oldPassword"], request["newPassword"])
        deleteUsersSessions(username)

        return {
            "success": True
        }
    except Exception as e:
        print(e)
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for signing up that only accepts post requests and
# data in the form of application/json
@app.route("/api/signUp", methods = ["POST"])
def signUp():
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Will validate the user's captcha token with hCaptcha and make sure the captcha was solved
        # on the same IP as the one making the request (CF-Connecting-IP is a header from CloudFlare
        # with the user's IP)
        if not checkCaptcha(request["captchaToken"], flask.request.headers.get("cf-connecting-ip")):
            return {
                "success": False,
                "error": "Invalid captcha token."
            }, 400
        
        # Will validate the username and password using the validation functions made previously
        if not validateUsername(request["username"]):
            return {
                "success": False,
                "error": "Username doesn't meet the requirements."
            }, 400

        if not validatePassword(request["password"]):
            return {
                "success": False,
                "error": "Password doesn't meet the requirements."
            }, 400
        
        # This will return an exception if the username doesn't exist so I've used that as a way to
        # check if a username is already in use by someone else
        try:
            getPasswordHash(request["username"])
            return {
                "success": False,
                "error": "Username is already taken."
            }, 400
        except:
            pass
        
        sessionToken = createUser(request["username"], request["password"])
        
        # Create a response object so I can set cookies
        response = flask.make_response({"success": True})
        response.set_cookie("authentication", sessionToken, max_age = 604800, secure = True)

        # Return the response
        return response
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Endpoint for logging in that only accepts post requests and
# data in the form of application/json
@app.route("/api/logIn", methods = ["POST"])
def logIn():
    try:
        # Tries to get the JSON from the request, will return an error if no JSON was passed in the
        # form application/json
        request = flask.request.get_json(force = True)

        # Will validate the user's captcha token with hCaptcha and make sure the captcha was solved
        # on the same IP as the one making the request (CF-Connecting-IP is a header from CloudFlare
        # with the user's IP)
        if not checkCaptcha(request["captchaToken"], flask.request.headers.get("cf-connecting-ip")):
            return {
                "success": False,
                "error": "Invalid captcha token."
            }, 400

        # Will validate the username and password using the validation functions made previously
        if not validateUsername(request["username"]):
            return {
                "success": False,
                "error": "Username doesn't meet the requirements."
            }, 400

        if not validatePassword(request["password"]):
            return {
                "success": False,
                "error": "Password doesn't meet the requirements."
            }, 400
        
        try:
            # Using the position of the fields in the users table to get the hashed password and
            # 2FA secret for the user logging in
            # This will jump to except if the username isn't found in the users table
            userInfo = getUserInfo(request["username"])
            hashedPassword = userInfo[1]
            twoFactorAuthenticationSecret = userInfo[6]
            
            if twoFactorAuthenticationSecret:
                if not validate2FACode(request["twoFactorAuthenticationCode"], twoFactorAuthenticationSecret):
                    return {
                        "success": False,
                        "error": "Incorrect credentials."
                    }, 400

            if verifyHash(hashedPassword, request["password"]):
                # Create a session for the user and get the user session token
                sessionToken = createSession(request["username"], request["password"])
                
                # Create a response object so I can set cookies
                response = flask.make_response({"success": True})
                response.set_cookie("authentication", sessionToken, max_age = 604800, secure = True)

                # Return the response
                return response
            else:
                return {
                    "success": False,
                    "error": "Incorrect credentials."
                }, 400
        except:
            return {
                "success": False,
                "error": "Incorrect credentials."
            }, 400
    except:
        return {
            "success": False,
            "error": "Internal server error."
        }, 500

# Frontend

@app.route("/")
def root():
    if flask.request.cookies.get("authentication"):
        if validateUserSessionToken(flask.request.cookies.get("authentication")):
            return flask.redirect("/dashboard")
        else:
            response = flask.make_response(readFile("frontend/index.html"))
            response.delete_cookie("authentication")
            return response

    return readFile("frontend/index.html")

@app.route("/style.css")
async def style():
    return readFile("frontend/style.css")

@app.route("/authentication.js")
def authentication():
    return readFile("frontend/authentication.js")

@app.route("/dashboard")
def dashboard():
    if not flask.request.cookies.get("authentication"):
        return flask.redirect("/")
    
    if not validateUserSessionToken(flask.request.cookies.get("authentication")):
        response = flask.make_response(flask.redirect("/"))
        response.delete_cookie("authentication")
        return response

    return readFile("frontend/dashboard.html")

@app.route("/dashboard.js")
def dashboardScript():
    return readFile("frontend/dashboard.js")

@app.route("/password/<id>")
def password(id):
    if not flask.request.cookies.get("authentication"):
        return flask.redirect("/")
    
    if not validateUserSessionToken(flask.request.cookies.get("authentication")):
        response = flask.make_response(flask.redirect("/"))
        response.delete_cookie("authentication")
        return response

    return readFile("frontend/password.html")

@app.route("/password.js")
def passwordScript():
    return readFile("frontend/password.js")

@app.route("/iconNames")
def iconNames():
    return readFile("data/iconNames.txt")

# Starts the web server with threading enabled and evalex disabled as
# it's related to debugging, which we don't want to avoid reverse
# engineering.
run_simple("0.0.0.0", 80, app, threaded = True, use_evalex = False)