/*
    The first four functions run when the username and password fields in the 'Sign Up' section of the page are selected or
    deselected to show and hide the requirements for those fields.

    The logIn and signUp functions will run when a captcha from their respective sections of the page is solved by the user.

    The getCaptcha function will run when the 'Submit' button is pressed in either section of the page.

    I made the logIn and signUp functions asynchronous so that I could make fetch requests because I've had problems before
    using fetch in synchronous functions.
*/

const hCaptchaSiteKey = ""

const codeCharSet = "0123456789"
const usernameCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const passwordCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "

const headers = new Headers()
headers.append("content-type", "application/json")

function showUsernameTip() {
    document.getElementById("usernameTip").hidden = false
}

function hideUsernameTip() {
    document.getElementById("usernameTip").hidden = true
}

function showPasswordTip() {
    document.getElementById("passwordTip").hidden = false
}

function hidePasswordTip() {
    document.getElementById("passwordTip").hidden = true
}

async function logIn(captchaToken) {
    const response = await fetch(
        "/api/logIn",
        {
            method: "POST",
            body: JSON.stringify({
                username: document.getElementById("logInUsername").value,
                password: document.getElementById("logInPassword").value,
                twoFactorAuthenticationCode: document.getElementById("logIn2FACode").value,
                captchaToken: captchaToken
            }),
            headers: headers
        }
    )

    // Check if the success in the returned JSON is set to true
    // and redirect to the dashboard if that's the case,
    // otherwise show a message with the error
    const responseJSON = await response.json()
    if (responseJSON.success) {
        window.location.href = "/dashboard"
    } else {
        alert("Error: " + responseJSON.error)
    }
}

async function signUp(captchaToken) {
    const response = await fetch(
        "/api/signUp",
        {
            method: "POST",
            body: JSON.stringify({
                username: document.getElementById("signUpUsername").value,
                password: document.getElementById("signUpPassword1").value,
                captchaToken: captchaToken
            }),
            headers: headers
        }
    )

    // Check if the success in the returned JSON is set to true
    // and redirect to the dashboard if that's the case,
    // otherwise show a message with the error
    const responseJSON = await response.json()
    if (responseJSON.success) {
        window.location.href = "/dashboard"
    } else {
        alert("Error: " + responseJSON.error)
    }
}

async function getCaptcha(captchaFor) {
    if (captchaFor == 1) {
        if (
            document.getElementById("logInUsername").value.length < 3
            || document.getElementById("logInUsername").value.length > 20
        ) {
            alert("Usernames must be between 3 and 20 characters long.")
            return
        }

        if (
            document.getElementById("logInPassword").value.length < 8
            || document.getElementById("logInPassword").value.length > 32
        ) {
            alert("Passwords must be between 8 and 32 characters long.")
            return
        }

        if (
            document.getElementById("logIn2FACode").value.length != 0
            && document.getElementById("logIn2FACode").value.length != 6
        ) {
            alert("You must either leave the 2FA code blank or enter a valid code.")
            return
        }

        for (let character of document.getElementById("logInUsername").value) {
            if (!usernameCharSet.includes(character)) {
                alert("Username contains invalid characters.")
                return
            }
        }

        for (let character of document.getElementById("logInPassword").value) {
            if (!passwordCharSet.includes(character)) {
                alert("Password contains invalid characters.")
                return
            }
        }

        for (let character of document.getElementById("logIn2FACode").value) {
            if (!codeCharSet.includes(character)) {
                alert("You must either leave the 2FA code blank or enter a valid code.")
                return
            }
        }

        document.getElementById("signUpForm").hidden = true
        document.getElementById("or").hidden = true
        document.getElementById("logInButton").disabled = true
        document.getElementById("logInUsername").disabled = true
        document.getElementById("logInPassword").disabled = true
        document.getElementById("logIn2FACode").disabled = true
        hcaptcha.render(
            "logInCaptcha",
            {
                sitekey: hCaptchaSiteKey,
                theme: "light"
            }
        )
    } else {
        if (document.getElementById("signUpPassword1").value != document.getElementById("signUpPassword2").value) {
            alert("Passwords don't match.")
            return
        }

        if (
            document.getElementById("signUpUsername").value.length < 3
            || document.getElementById("signUpUsername").value.length > 20
        ) {
            alert("Usernames must be between 3 and 20 characters long.")
            return
        }

        if (
            document.getElementById("signUpPassword1").value.length < 8
            || document.getElementById("signUpPassword1").value.length > 32
        ) {
            alert("Passwords must be between 8 and 32 characters long.")
            return
        }

        for (let character of document.getElementById("signUpUsername").value) {
            if (!usernameCharSet.includes(character)) {
                alert("Username contains invalid characters.")
                return
            }
        }

        for (let character of document.getElementById("signUpPassword1").value) {
            if (!passwordCharSet.includes(character)) {
                alert("Password contains invalid characters.")
                return
            }
        }

        document.getElementById("or").hidden = true
        document.getElementById("signUpButton").disabled = true
        document.getElementById("logInButton").disabled = true
        document.getElementById("logInForm").hidden = true
        hcaptcha.render(
            "signUpCaptcha",
            {
                sitekey: hCaptchaSiteKey,
                theme: "light"
            }
        )
    }
}