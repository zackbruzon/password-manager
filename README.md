# Setup
You'll first need to create a hCaptcha account, you can do that by clicking [here](https://dashboard.hcaptcha.com/signup). Add a new site and make note of the sitekey and secret. In `/main.py`, enter your sitekey and secret into the empty constants, and do the same with your sitekey in `/frontend/authentication.js`.

After that, install the requirements using `pip install -r requirements.txt` and run `/data/setupDatabase.py`.

Finally, run `/main.py` to start the password manager.
# Demo
I'm hosting it on [coolpasswordmanager.xyz](https://coolpasswordmanager.xyz) to be tried out.
