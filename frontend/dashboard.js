// Character set for passwords
const passwordCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "

// Character set for 2FA secrets
const secretCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// Character set for 2FA codes
const codeCharSet = "0123456789"

// Character set for password names
const passwordNameCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

// Sets the content type to 'application/json' so the webserver accepts the data
const headers = new Headers()
headers.append("content-type", "application/json")

// Generates a 2FA secret
function generateSecret() {
    let secret = ""
    for (let i = 0; i < 32; i++) {
        secret = secret + secretCharSet.charAt(Math.floor(Math.random() * secretCharSet.length))
    }
    return secret
}

document.getElementById("enable2FASecret").value = generateSecret()

// Fires when the change password button is clicked
async function changePassword() {
    // Same input validation from the sign up page
    if (
        document.getElementById("changePasswordNew1").value.length < 8
        || document.getElementById("changePasswordNew1").value.length > 32
    ) {
        alert("Passwords must be between 8 and 32 characters long.")
        return
    }

    for (let character of document.getElementById("changePasswordNew1").value) {
        if (!passwordCharSet.includes(character)) {
            alert("Password contains invalid characters.")
            return
        }
    }

    if (document.getElementById("changePasswordNew1").value != document.getElementById("changePasswordNew2").value) {
        alert("Passwords don't match.")
        return
    }

    // Sends the request to change the password
    const request = await fetch(
        "/api/changePassword",
        {
            method: "POST",
            body: JSON.stringify({
                "oldPassword": document.getElementById("changePasswordOld").value,
                "newPassword": document.getElementById("changePasswordNew1").value
            }),
            headers: headers
        }
    )

    // Gets the JSON from the response
    const response = await request.json()
    
    // Checks if it was successful
    if (response.success) {
        alert("Successfully changed password, please log back in.")
        window.location.href = "/"
    } else {
        alert("Error: " + response.error)
    }
}

// Fires when the enable 2FA button is clicked
async function enable2FA() {
    // Validate the inputs
    if (document.getElementById("enable2FASecret").value.length != 32) {
        alert("Invalid secret.")
        return
    }

    for (let character of document.getElementById("enable2FASecret").value) {
        if (!secretCharSet.includes(character)) {
            alert("Invalid secret.")
            return
        }
    }

    if (document.getElementById("enable2FACode").value.length != 6) {
        alert("You must enter a six-digit code.")
        return
    }

    for (let character of document.getElementById("enable2FACode").value) {
        if (!codeCharSet.includes(character)) {
            alert("You must enter a six-digit code.")
            return
        }
    }

    // Sends the request to enable 2FA
    const request = await fetch(
        "/api/enable2FA",
        {
            method: "POST",
            body: JSON.stringify({
                "secret": document.getElementById("enable2FASecret").value,
                "code": document.getElementById("enable2FACode").value
            }),
            headers: headers
        }
    )

    // Gets the JSON from the response
    const response = await request.json()

    // Checks if it was successful
    if (response.success) {
        document.getElementById("enable2FA").hidden = true
        document.getElementById("disable2FA").hidden = false

        alert("Successfully enabled 2FA.")
    } else {
        alert("Error: " + response.error)
    }
}

// Fires when the disable 2FA button is clicked
async function disable2FA() {
    // Validate the input
    if (
        document.getElementById("disable2FACode").value.length != 0
        && document.getElementById("disable2FACode").value.length != 6
    ) {
        alert("You must enter a six-digit code.")
        return
    }

    for (let character of document.getElementById("disable2FACode").value) {
        if (!codeCharSet.includes(character)) {
            alert("You must enter a six-digit code.")
            return
        }
    }

    // Sends the request to disable 2FA
    const request = await fetch(
        "/api/disable2FA",
        {
            method: "POST",
            body: JSON.stringify({
                "code": document.getElementById("disable2FACode").value
            }),
            headers: headers
        }
    )

    // Gets the JSON from the response
    const response = await request.json()

    // Checks if it was successful
    if (response.success) {
        document.getElementById("disable2FA").hidden = true
        document.getElementById("enable2FA").hidden = false

        alert("Successfully disabled 2FA.")
    } else {
        alert("Error: " + response.error)
    }
}

// Log out the user
async function logOut() {
    const request = await fetch("/api/logOut")
    const response = await request.json()

    if (response.success) {
        window.location.href = "/"
    } else {
        alert("Error: " + response.error)
    }
}

// Character types for generating passwords
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numbers = "0123456789"
const punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "

function generatePassword() {
    var password = []

    if (!isNaN(document.getElementById("letterCount").value)) {
        for (var i = 0; i < document.getElementById("letterCount").value; i++) {
            password.push(letters[Math.floor(Math.random() * letters.length)])
        }
    }

    if (!isNaN(document.getElementById("numberCount").value)) {
        for (var i = 0; i < document.getElementById("numberCount").value; i++) {
            password.push(numbers[Math.floor(Math.random() * numbers.length)])
        }
    }

    if (!isNaN(document.getElementById("punctuationCount").value)) {
        for (var i = 0; i < document.getElementById("punctuationCount").value; i++) {
            password.push(punctuation[Math.floor(Math.random() * punctuation.length)])
        }
    }

    var password2 = ""

    while (password.length > 0) {
        var index = Math.floor(Math.random() * password.length)
        password2 = password2 + password[index]
        password.splice(index, 1)
    }

    document.getElementById("generatedPasswordValue").value = password2
}

// Validate inputs and create the password
async function createPassword() {
    // Check whether the user is using a generated password or their own
    var passwordElement = "passwordValue"
    if (document.getElementById("useGeneratedPassword").checked) {
        passwordElement = "generatedPasswordValue"
    }

    // Validate password
    if (
        document.getElementById(passwordElement).value.length < 8
        || document.getElementById(passwordElement).value.length > 64
    ) {
        alert("Stored passwords must be between 8 and 64 characters long.")
        return
    }

    for (let character of document.getElementById(passwordElement).value) {
        if (!passwordCharSet.includes(character)) {
            alert("Password contains invalid characters.")
            return
        }
    }

    // Validate password name
    if (
        document.getElementById("passwordName").value.length < 3
        || document.getElementById("passwordName").value.length > 20
    ) {
        alert("Password names must be between 3 and 20 characters long.")
        return
    }

    for (let character of document.getElementById("passwordName").value) {
        if (!passwordNameCharSet.includes(character)) {
            alert("Password name contains invalid characters.")
            return
        }
    }

    // Send request to create password
    const request = await fetch(
        "/api/createPassword",
        {
            method: "POST",
            body: JSON.stringify({
                "name": document.getElementById("passwordName").value,
                "icon": document.getElementById("passwordIcon").value,
                "password": document.getElementById(passwordElement).value
            }),
            headers: headers
        }
    )

    // Get response and redirect to password's page if successful, otherwise tell user what went wrong
    const response = await request.json()

    if (response.success) {
        window.location.href = "/password/" + response.id
    } else {
        alert("Error: " + response.error)
    }
}

// Validates session inactivity threshold and attempts to change it
async function setSessionInactivityThreshold() {
    if (isNaN(document.getElementById("sessionInactivityThreshold").value)) {
        alert("Error: Session inactivity threshold must be a number.")
        return
    }

    const sessionInactivityThreshold = Number(document.getElementById("sessionInactivityThreshold").value)

    if (
        sessionInactivityThreshold >= 30 &&
        sessionInactivityThreshold <= 86400
    ) {
        // Send request to create password
        const request = await fetch(
            "/api/setSessionInactivityThreshold",
            {
                method: "POST",
                body: JSON.stringify({
                    "sessionInactivityThreshold": sessionInactivityThreshold
                }),
                headers: headers
            }
        )

        // Get response and tell the user if successful, otherwise tell user what went wrong
        const response = await request.json()

        if (response.success) {
            alert("Successfully changed your session inactivity threshold.")
        } else {
            alert("Error: " + response.error)
        }
    } else {
        alert("Error: Session inactivity threshold must be between 30 and 86400 seconds.")
        return
    }
}

// Show options for the user's own password or a generated one depending on what they choose
function passwordTypeChanged() {
    if (document.getElementById("useGeneratedPassword").checked) {
        document.getElementById("userPassword").hidden = true
        document.getElementById("generatedPassword").hidden = false
    } else {
        document.getElementById("userPassword").hidden = false
        document.getElementById("generatedPassword").hidden = true
    }
}

// Change to whichever page the user chooses
function showCreatePassword() {
    document.getElementById("passwordCreation").hidden = false
    document.getElementById("passwordList").hidden = true
    document.getElementById("settings").hidden = true
}

function showPasswordList() {
    document.getElementById("passwordList").hidden = false
    document.getElementById("passwordCreation").hidden = true
    document.getElementById("settings").hidden = true
}

function showSettings() {
    document.getElementById("settings").hidden = false
    document.getElementById("passwordList").hidden = true
    document.getElementById("passwordCreation").hidden = true
}

// Show and hide password tip when creating a new password
function showPasswordTip() {
    document.getElementById("passwordTip").hidden = false
}

function hidePasswordTip() {
    document.getElementById("passwordTip").hidden = true
}

// Get the user's passwords and add them to the password list (if there are any)
async function getPasswords() {
    const request = await fetch("/api/getPasswords")
    const response = await request.json()

    if (response.success) {
        // Check if the user's made any passwords and tell them if they haven't
        if (response.passwords.length == 0) {
            document.getElementById("loadingMessage").innerHTML = "You haven't made a password yet, make one and it'll appear here."
            return
        }

        // Hide loading message
        document.getElementById("loadingMessage").hidden = true

        // Create elements for each password
        for (var i = 0; i < response.passwords.length; i++) {
            var password = document.createElement("a")
            password.href = "/password/" + response.passwords[i].id
            password.innerHTML = "<h4>"
            
            if (response.passwords[i].icon != "none") {
                icon = response.passwords[i].icon.split("/")[0]
                style = response.passwords[i].icon.split("/")[1]

                password.innerHTML = password.innerHTML + "<i class=\"fa-" + style + " fa-" + icon + "\"></i>"
            }

            password.innerHTML = password.innerHTML + " " + response.passwords[i].name + "</h4>"
            document.getElementById("passwordList").appendChild(password)
        }
    } else {
        alert("Error: " + response.error)
    }
}

getPasswords()

async function getIconNames() {
    const request = await fetch("/iconNames")
    const response = await request.text()
    const iconNames = response.split("\n")

    for (var i = 0; i < iconNames.length; i++) {
        var option = document.createElement("option")
        option.value = iconNames[i]
        option.innerHTML = iconNames[i].split("/")[0] + " (" + iconNames[i].split("/")[1] + ")"
        document.getElementById("passwordIcon").appendChild(option)
    }
}

getIconNames()

async function check2FA() {
    const request = await fetch("/api/check2FA")
    const response = await request.json()

    if (response.success) {
        if (response.enabled) {
            document.getElementById("disable2FA").hidden = false
            document.getElementById("enable2FA").hidden = true
        }
    } else if (response.error == "Unauthorised.") {
        window.location.href = "/"
    }
}

check2FA()