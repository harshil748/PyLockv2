import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import os
import secrets
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

backend = default_backend()


class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect("passwords.db")
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT,
                email TEXT,
                phone TEXT,
                verified INTEGER DEFAULT 0
            )
        """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                service TEXT,
                username TEXT,
                password TEXT,
                iv TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """
        )
        self.conn.commit()

    def execute_query(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        return cursor


class AuthManager:
    @staticmethod
    def hash_password(password, salt=None):
        salt = salt or os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), salt.hex()

    @staticmethod
    def generate_verification_code():
        return "".join(secrets.choice(string.digits) for _ in range(6))


class EncryptionManager:
    @staticmethod
    def encrypt_password(password, master_key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(master_key), modes.CFB(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(password.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(ct).decode(), iv.hex()

    @staticmethod
    def decrypt_password(encrypted_password, iv, master_key):
        iv = bytes.fromhex(iv)
        ct = base64.urlsafe_b64decode(encrypted_password)
        cipher = Cipher(algorithms.AES(master_key), modes.CFB(iv), backend=backend)
        decryptor = cipher.decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode()


class LoginWindow:
    def __init__(self, master, db_manager, auth_manager, on_login_success):
        self.master = master
        self.db_manager = db_manager
        self.auth_manager = auth_manager
        self.on_login_success = on_login_success

        self.frame = ttk.Frame(self.master, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(self.frame, text="Username:").grid(
            column=0, row=0, sticky=tk.W, pady=5
        )
        self.username_entry = ttk.Entry(self.frame, width=30)
        self.username_entry.grid(column=1, row=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.frame, text="Password:").grid(
            column=0, row=1, sticky=tk.W, pady=5
        )
        self.password_entry = ttk.Entry(self.frame, show="*", width=30)
        self.password_entry.grid(column=1, row=1, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(self.frame, text="Login", command=self.login).grid(
            column=1, row=2, sticky=tk.E, pady=10
        )
        ttk.Button(self.frame, text="Register", command=self.open_registration).grid(
            column=0, row=2, sticky=tk.W, pady=10
        )

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        user = self.db_manager.execute_query(
            """
            SELECT id, password_hash, salt FROM users WHERE username = ?
        """,
            (username,),
        ).fetchone()

        if user:
            stored_key = user[1]
            salt = bytes.fromhex(user[2])
            derived_key, _ = self.auth_manager.hash_password(password, salt)

            if derived_key == stored_key:
                self.on_login_success(user)
                return

        messagebox.showerror("Error", "Invalid credentials")

    def open_registration(self):
        registration_window = tk.Toplevel(self.master)
        RegistrationWindow(registration_window, self.db_manager, self.auth_manager)


class RegistrationWindow:
    def __init__(self, master, db_manager, auth_manager):
        self.master = master
        self.db_manager = db_manager
        self.auth_manager = auth_manager

        self.master.title("Register")
        self.frame = ttk.Frame(self.master, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(self.frame, text="Username:").grid(
            column=0, row=0, sticky=tk.W, pady=5
        )
        self.username_entry = ttk.Entry(self.frame, width=30)
        self.username_entry.grid(column=1, row=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.frame, text="Password:").grid(
            column=0, row=1, sticky=tk.W, pady=5
        )
        self.password_entry = ttk.Entry(self.frame, show="*", width=30)
        self.password_entry.grid(column=1, row=1, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.frame, text="Email:").grid(column=0, row=2, sticky=tk.W, pady=5)
        self.email_entry = ttk.Entry(self.frame, width=30)
        self.email_entry.grid(column=1, row=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.frame, text="Phone:").grid(column=0, row=3, sticky=tk.W, pady=5)
        self.phone_entry = ttk.Entry(self.frame, width=30)
        self.phone_entry.grid(column=1, row=3, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(self.frame, text="Register", command=self.register).grid(
            column=1, row=4, sticky=tk.E, pady=10
        )

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        email = self.email_entry.get()
        phone = self.phone_entry.get()

        if not all([username, password, email, phone]):
            messagebox.showerror("Error", "All fields are required")
            return

        derived_key, salt = self.auth_manager.hash_password(password)

        try:
            self.db_manager.execute_query(
                """
                INSERT INTO users (username, password_hash, salt, email, phone)
                VALUES (?, ?, ?, ?, ?)
            """,
                (username, derived_key, salt, email, phone),
            )

            messagebox.showinfo(
                "Success", "Registration successful! Please verify your account."
            )
            self.master.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")


class MainWindow:
    def __init__(self, master, db_manager, encryption_manager, user):
        self.master = master
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.user = user

        self.master.title("Password Manager")
        self.frame = ttk.Frame(self.master, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.notebook = ttk.Notebook(self.frame)
        self.notebook.grid(row=0, column=0, columnspan=2, pady=10)

        self.add_password_tab = ttk.Frame(self.notebook)
        self.retrieve_password_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.add_password_tab, text="Add Password")
        self.notebook.add(self.retrieve_password_tab, text="Retrieve Password")

        self.setup_add_password_tab()
        self.setup_retrieve_password_tab()

        ttk.Button(self.frame, text="Logout", command=self.logout).grid(
            column=1, row=1, sticky=tk.E, pady=10
        )

    def setup_add_password_tab(self):
        ttk.Label(self.add_password_tab, text="Service:").grid(
            column=0, row=0, sticky=tk.W, pady=5
        )
        self.service_entry = ttk.Entry(self.add_password_tab, width=30)
        self.service_entry.grid(column=1, row=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.add_password_tab, text="Username:").grid(
            column=0, row=1, sticky=tk.W, pady=5
        )
        self.username_entry = ttk.Entry(self.add_password_tab, width=30)
        self.username_entry.grid(column=1, row=1, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.add_password_tab, text="Password:").grid(
            column=0, row=2, sticky=tk.W, pady=5
        )
        self.password_entry = ttk.Entry(self.add_password_tab, show="*", width=30)
        self.password_entry.grid(column=1, row=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(
            self.add_password_tab,
            text="Generate Password",
            command=self.generate_password,
        ).grid(column=1, row=3, sticky=tk.E, pady=5)
        ttk.Button(self.add_password_tab, text="Save", command=self.save_password).grid(
            column=1, row=4, sticky=tk.E, pady=5
        )

    def setup_retrieve_password_tab(self):
        ttk.Label(self.retrieve_password_tab, text="Service:").grid(
            column=0, row=0, sticky=tk.W, pady=5
        )
        self.retrieve_service_entry = ttk.Entry(self.retrieve_password_tab, width=30)
        self.retrieve_service_entry.grid(column=1, row=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(
            self.retrieve_password_tab, text="Retrieve", command=self.retrieve_password
        ).grid(column=1, row=1, sticky=tk.E, pady=5)

        self.retrieve_result = ttk.Label(self.retrieve_password_tab, text="")
        self.retrieve_result.grid(column=0, row=2, columnspan=2, pady=10)

    def generate_password(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        password = "".join(secrets.choice(chars) for _ in range(16))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def save_password(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        encrypted_password, iv = self.encryption_manager.encrypt_password(
            password, base64.urlsafe_b64decode(self.user[1])
        )

        self.db_manager.execute_query(
            """
            INSERT INTO passwords (user_id, service, username, password, iv)
            VALUES (?, ?, ?, ?, ?)
        """,
            (self.user[0], service, username, encrypted_password, iv),
        )

        messagebox.showinfo("Success", "Password saved successfully")
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def retrieve_password(self):
        service = self.retrieve_service_entry.get()
        result = self.db_manager.execute_query(
            """
            SELECT username, password, iv FROM passwords
            WHERE user_id = ? AND service = ?
        """,
            (self.user[0], service),
        ).fetchone()

        if result:
            username, encrypted_password, iv = result
            decrypted_password = self.encryption_manager.decrypt_password(
                encrypted_password, iv, base64.urlsafe_b64decode(self.user[1])
            )
            self.retrieve_result.config(
                text=f"Username: {username}\nPassword: {decrypted_password}"
            )
        else:
            messagebox.showerror("Error", "No password found for this service")

    def logout(self):
        self.master.destroy()


class PasswordManagerApp:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.auth_manager = AuthManager()
        self.encryption_manager = EncryptionManager()

        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.geometry("1080x720")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.theme_use("aqua")

        self.show_login_window()

    def show_login_window(self):
        LoginWindow(
            self.root, self.db_manager, self.auth_manager, self.on_login_success
        )

    def on_login_success(self, user):
        for widget in self.root.winfo_children():
            widget.destroy()
        MainWindow(self.root, self.db_manager, self.encryption_manager, user)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.run()
