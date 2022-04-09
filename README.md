# pyStitchClient

A Python implementation of a client using the user token flow for [Stitch Money](https://stitch.money/)
Documentation [here](https://stitch.money/docs/stitch-sso/user-tokens).

Usage:
* Copy .env.example to .env and fill in your client ID
* Copy your certificate to the root folder (make sure it's in .gitignore if you name it differently)
* Run: python stitch.py

TODO:
* Add code for callback listener using FastAPI 
