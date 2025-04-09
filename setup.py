from setuptools import setup

APP = ["main.py"]  # Replace with your main filename if different
DATA_FILES = ["passwords.db"]  # Your SQLite DB (adjust name if needed)
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
    "resources": ["database.db"],
    "iconfile": "icon.icns",  # Optional - include your own icon file or remove this line
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
