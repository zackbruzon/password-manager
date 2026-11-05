// Get the password identifier from URL
const passwordId = window.location.pathname.split("/").at(-1)

// Sets the content type to 'application/json' so the webserver accepts the data
const headers = new Headers()
headers.append("content-type", "application/json")

// Character sets for passwords and password names
const passwordCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "
const passwordNameCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

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

// Validate inputs and edit password
async function editPassword() {
    var passwordElement = "editPasswordBox"
    if (document.getElementById("useGeneratedPassword").checked) {
        passwordElement = "generatedPasswordValue"
    }

    var payload = {}

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
        document.getElementById("editPasswordName").value.length < 3
        || document.getElementById("editPasswordName").value.length > 20
    ) {
        alert("Password names must be between 3 and 20 characters long.")
        return
    }

    for (let character of document.getElementById("editPasswordName").value) {
        if (!passwordNameCharSet.includes(character)) {
            alert("Password name contains invalid characters.")
            return
        }
    }

    // Add values that were changed to the payload
    if (document.getElementById("editPasswordName").value != document.getElementById("passwordName").value) {
        payload["name"] = document.getElementById("editPasswordName").value
    }

    if (document.getElementById("editPasswordIcon").value != document.getElementById("passwordIcon").getAttribute("iconvalue")) {
        payload["icon"] = document.getElementById("editPasswordIcon").value
    }

    if (document.getElementById(passwordElement).value != document.getElementById("passwordBox").value) {
        payload["password"] = document.getElementById(passwordElement).value
    }

    // Send request to edit password
    const request = await fetch(
        "/api/editPassword/" + passwordId,
        {
            method: "POST",
            body: JSON.stringify(payload),
            headers: headers
        }
    )

    const response = await request.json()

    if (response.success) {
        alert("Successfully edited password.")
        window.location.href = "/dashboard"
    } else {
        alert("Error: " + response.error)
        window.location.href = "/dashboard"
    }
}

// Deletes the password
async function deletePassword() {
    // Send request to delete password
    const request = await fetch("/api/deletePassword/" + passwordId)
    const response = await request.json()

    if (response.success) {
        alert("Successfully deleted password.")
        window.location.href = "/dashboard"
    } else {
        alert("Error: " + response.error)
    }
}

// Show or hide the form to edit the password
function showEditForm() {
    document.getElementById("passwordInfoOuter").hidden = true
    document.getElementById("editPassword").hidden = false
}

function hideEditForm() {
    document.getElementById("editPassword").hidden = true
    document.getElementById("passwordInfoOuter").hidden = false
}

async function getIconNames() {
    const request = await fetch("/iconNames")
    const response = await request.text()
    const iconNames = response.split("\n")

    for (var i = 0; i < iconNames.length; i++) {
        var option = document.createElement("option")
        option.value = iconNames[i]
        option.innerHTML = iconNames[i].split("/")[0] + " (" + iconNames[i].split("/")[1] + ")"
        document.getElementById("editPasswordIcon").appendChild(option)
    }
}

getIconNames()

async function buildPage() {
    // Request the password's info
    const request = await fetch("/api/getPasswordInfo/" + passwordId)
    const response = await request.json()

    if (response.success) {
        var icon = document.createElement("i")

        if (response.info.icon != "none") {
            iconName = response.info.icon.split("/")[0]
            iconStyle = response.info.icon.split("/")[1]

            icon.classList.add("fa-" + iconStyle)
            icon.classList.add("fa-" + iconName)
            icon.style = "height: 10rem;"
        }
            
        icon.id = "passwordIcon"
        icon.setAttribute("iconvalue", response.info.icon)

        document.getElementById("passwordInfo").appendChild(icon)
        document.getElementById("editPasswordIcon").value = response.info.icon

        var passwordName = document.createElement("h3")
        passwordName.innerHTML = response.info.name
        passwordName.id = "passwordName"
        document.getElementById("passwordInfo").appendChild(passwordName)
        document.getElementById("editPasswordName").value = response.info.name

        var gap = document.createElement("br")
        document.getElementById("passwordInfo").appendChild(gap)

        var passwordBoxLabel = document.createElement("h4")
        passwordBoxLabel.innerHTML = "Password"
        document.getElementById("passwordInfo").appendChild(passwordBoxLabel)

        var passwordBox = document.createElement("input")
        passwordBox.disabled = true
        passwordBox.value = response.info.password
        passwordBox.id = "passwordBox"
        document.getElementById("passwordInfo").appendChild(passwordBox)
        document.getElementById("editPasswordBox").value = response.info.password
    } else {
        alert("Error: " + response.error)
        window.location.href = "/dashboard"
    }
}

buildPage()