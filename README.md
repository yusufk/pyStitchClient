# pyStitchClient

A Python implementation of a client using the user token flow for [Stitch Money](https://stitch.money/)
Documentation [here](https://stitch.money/docs/stitch-sso/user-tokens).

This project uses [poetry](https://python-poetry.org/).

Usage:
* Copy .env.example to .env and fill in your client ID
* Copy your certificate to the root folder (make sure it's in .gitignore if you name it differently)
* Start the callback listener: python -m http.server 9000
* Run: poetry install
* Run: poetry run python pystitchclient/stitch.py
* A browser window should open, complete the login process.
* Copy and paste the callback code into the shell and hit enter

[![asciicast](https://asciinema.org/a/z5Ag6afED73YQGob324HKebak.svg)](https://asciinema.org/a/z5Ag6afED73YQGob324HKebak)

Hint: 
If you've already succesfully generated a token and want to call teh API, you can use:
python python pystitchclient/stitch.py <token> to skip the steps to regenerate the token.

The code will run few the steps of getting the required tokens and at some point will prompt for the access code from the user. This will need to be collected from the callback API (not yet implemented here).

TODO:
* Make the callback handler a little prettier 
* Add token refresh logic
