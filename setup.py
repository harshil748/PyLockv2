from setuptools import setup

APP = ["main.py"]  
DATA_FILES = ["passwords.db"]  
OPTIONS = {
    "argv_emulation": True,
    "packages": [
        "cryptography",
        "email",
    ],
    "includes": [
        "tkinter",
        "sqlite3",
        "hashlib",
        "os",
        "secrets",
        "string",
        "base64",
        "smtplib",
    ],
    "resources": ["passwords.db"],
    "iconfile": "icon.icns",
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
