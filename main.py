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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

backend = default_backend()

# Email configuration
SENDER_EMAIL = "sgp.noreplydce@gmail.com"
SENDER_PASSWORD = "haub ylen jpof ypse"


class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect("passwords.db")
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()

        # Create users table with verification_code and special_sentence columns
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT,
                email TEXT,
                phone TEXT,
                verified INTEGER DEFAULT 0,
                verification_code TEXT,
                special_sentence TEXT
            )
            """
        )

        # Make sure the verification_code and special_sentence columns exist (for older databases)
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN verification_code TEXT")
        except sqlite3.OperationalError:
            # Column already exists, ignore
            pass

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN special_sentence TEXT")
        except sqlite3.OperationalError:
            # Column already exists, ignore
            pass

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                service TEXT,
                username TEXT,
                password TEXT,
                iv TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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

    @staticmethod
    def send_verification_email(receiver_email, code):
        subject = "Your Password Manager Verification Code"
        body = f"""
        Your verification code is: {code}
        
        Please enter this code to verify your account.
        If you did not request this code, please ignore this email.
        """

        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = receiver_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            print(f"Attempting to send email to {receiver_email}")
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.ehlo()  # Identify to SMTP server
            server.starttls()  # Secure connection
            print("Logging into SMTP server...")
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            print("Sending email...")
            server.send_message(msg)
            server.quit()
            print("Email sent successfully")
            return True
        except Exception as e:
            print(f"Email failed to send: {e}")
            messagebox.showerror(
                "Error", f"Failed to send verification email: {str(e)}"
            )
            return False

    @staticmethod
    def generate_special_sentence():
        words = [
            "apple",
            "banana",
            "cherry",
            "date",
            "blueberry",
            "fig",
            "grape",
            "honeydew",
        ]
        return " ".join(secrets.choice(words) for _ in range(6))



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
        ttk.Button(
            self.frame, text="Forgot Password", command=self.open_reset_password
        ).grid(column=1, row=3, sticky=tk.E, pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        user = self.db_manager.execute_query(
            """
            SELECT id, password_hash, salt, verified, email FROM users WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user:
            stored_key = user[1]
            salt = bytes.fromhex(user[2])
            derived_key, _ = self.auth_manager.hash_password(password, salt)

            if derived_key == stored_key:
                if user[3] == 0:  # If not verified
                    verification_window = tk.Toplevel(self.master)
                    VerificationWindow(
                        verification_window,
                        self.db_manager,
                        self.auth_manager,
                        username,
                        user[4],  # email
                        lambda: self.on_login_success(user),
                    )
                    return
                self.on_login_success(user)
                return

        messagebox.showerror("Error", "Invalid credentials")

    def open_registration(self):
        registration_window = tk.Toplevel(self.master)
        RegistrationWindow(registration_window, self.db_manager, self.auth_manager)

    def open_reset_password(self):
        reset_password_window = tk.Toplevel(self.master)
        ResetPasswordWindow(reset_password_window, self.db_manager, self.auth_manager)


class VerificationWindow:
    def __init__(
        self, master, db_manager, auth_manager, username, email, on_verify_success
    ):
        self.master = master
        self.db_manager = db_manager
        self.auth_manager = auth_manager
        self.username = username
        self.email = email
        self.on_verify_success = on_verify_success

        # Set window properties
        self.master.title("Verify Account")
        self.master.geometry("400x250")
        self.frame = ttk.Frame(self.master, padding="20")
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Create status variable
        self.status_var = tk.StringVar()
        self.status_var.set("Sending verification code...")

        ttk.Label(
            self.frame, text="Email Verification", font=("Arial", 16, "bold")
        ).pack(pady=(0, 20))

        ttk.Label(
            self.frame, text=f"A verification code has been sent to:\n{email}"
        ).pack(pady=(0, 20))

        code_frame = ttk.Frame(self.frame)
        code_frame.pack(fill=tk.X, pady=10)

        ttk.Label(code_frame, text="Enter Code:").pack(side=tk.LEFT, padx=5)
        self.code_entry = ttk.Entry(code_frame, width=10, font=("Arial", 14))
        self.code_entry.pack(side=tk.LEFT, padx=5)

        button_frame = ttk.Frame(self.frame)
        button_frame.pack(fill=tk.X, pady=20)

        ttk.Button(button_frame, text="Verify", command=self.verify).pack(
            side=tk.RIGHT, padx=5
        )

        ttk.Button(button_frame, text="Resend Code", command=self.resend_code).pack(
            side=tk.RIGHT, padx=5
        )

        # Status label
        self.status_label = ttk.Label(
            self.frame, textvariable=self.status_var, foreground="gray"
        )
        self.status_label.pack(pady=10)

        # Generate and send verification code
        self.master.after(500, self.send_verification)

    def send_verification(self):
        verification_code = self.auth_manager.generate_verification_code()
        print(
            f"Generated verification code: {verification_code} for user {self.username}"
        )

        # Save code in database
        self.db_manager.execute_query(
            """
            UPDATE users SET verification_code = ? WHERE username = ?
            """,
            (verification_code, self.username),
        )

        # Send email
        success = self.auth_manager.send_verification_email(
            self.email, verification_code
        )

        if success:
            self.status_var.set("Verification code sent! Please check your email.")
        else:
            self.status_var.set("Failed to send code. Click Resend to try again.")

    def resend_code(self):
        self.status_var.set("Sending new verification code...")
        self.master.update_idletasks()
        self.send_verification()

    def verify(self):
        code = self.code_entry.get().strip()
        if not code:
            messagebox.showerror("Error", "Please enter the verification code")
            return

        print(f"Checking verification code: {code} for user {self.username}")

        user = self.db_manager.execute_query(
            """
            SELECT id, verification_code, special_sentence FROM users WHERE username = ?
            """,
            (self.username,),
        ).fetchone()

        if user and user[1] == code:
            print(f"Verification successful for user {self.username}")
            self.db_manager.execute_query(
                """
                UPDATE users SET verified = 1 WHERE id = ?
                """,
                (user[0],),
            )

            # Display special sentence in a new window
            special_sentence = user[2]
            self.display_special_sentence(special_sentence)

            messagebox.showinfo("Success", "Account verified successfully!")
            self.master.destroy()
            self.on_verify_success()
        else:
            stored_code = user[1] if user and user[1] else "No code found"
            print(f"Verification failed. Entered: {code}, Stored: {stored_code}")
            messagebox.showerror("Error", "Invalid verification code")
            self.status_var.set("Invalid code. Please try again.")

    def display_special_sentence(self, special_sentence):
        sentence_window = tk.Toplevel()
        sentence_window.title("Your Special Sentence")
        sentence_window.geometry("500x300")

        frame = ttk.Frame(sentence_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text="IMPORTANT: Save Your Special Sentence",
            font=("Arial", 14, "bold"),
        ).pack(pady=(0, 20))

        ttk.Label(
            frame,
            text="This sentence can be used to reset your password if you forget it.\nPlease save it in a secure location.",
            wraplength=400,
            justify=tk.CENTER,
        ).pack(pady=(0, 20))

        sentence_frame = ttk.Frame(frame)
        sentence_frame.pack(fill=tk.X, pady=10)

        sentence_text = ttk.Entry(sentence_frame, width=40, font=("Arial", 12))
        sentence_text.insert(0, special_sentence)
        sentence_text.configure(state="readonly")
        sentence_text.pack(pady=10)

        ttk.Button(
            frame, text="I've Saved My Sentence", command=sentence_window.destroy
        ).pack(pady=20)


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
        verification_code = self.auth_manager.generate_verification_code()
        special_sentence = self.auth_manager.generate_special_sentence()

        try:
            # Insert the user without verification code first
            self.db_manager.execute_query(
                """
                INSERT INTO users (username, password_hash, salt, email, phone, verified, special_sentence)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (username, derived_key, salt, email, phone, special_sentence),
            )

            # Generate verification code and update the user
            verification_code = self.auth_manager.generate_verification_code()
            self.db_manager.execute_query(
                """
                UPDATE users SET verification_code = ? WHERE username = ?
                """,
                (verification_code, username),
            )


            # Close registration window
            self.master.destroy()

            # Open verification window immediately
            verification_window = tk.Toplevel(self.master.master)
            VerificationWindow(
                verification_window,
                self.db_manager,
                self.auth_manager,
                username,
                email,
                lambda: messagebox.showinfo(
                    "Success", "You can now log in with your credentials."
                ),
            )

        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")


class ResetPasswordWindow:
    def __init__(self, master, db_manager, auth_manager):
        self.master = master
        self.db_manager = db_manager
        self.auth_manager = auth_manager

        self.master.title("Reset Password")
        self.frame = ttk.Frame(self.master, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(self.frame, text="Username:").grid(
            column=0, row=0, sticky=tk.W, pady=5
        )
        self.username_entry = ttk.Entry(self.frame, width=30)
        self.username_entry.grid(column=1, row=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.frame, text="Special Sentence:").grid(
            column=0, row=1, sticky=tk.W, pady=5
        )
        self.sentence_entry = ttk.Entry(self.frame, width=30)
        self.sentence_entry.grid(column=1, row=1, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(self.frame, text="New Password:").grid(
            column=0, row=2, sticky=tk.W, pady=5
        )
        self.new_password_entry = ttk.Entry(self.frame, show="*", width=30)
        self.new_password_entry.grid(column=1, row=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(self.frame, text="Reset Password", command=self.reset_password).grid(
            column=1, row=3, sticky=tk.E, pady=10
        )

    def reset_password(self):
        username = self.username_entry.get()
        special_sentence = self.sentence_entry.get()
        new_password = self.new_password_entry.get()

        user = self.db_manager.execute_query(
            """
            SELECT id, special_sentence FROM users WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user and user[1] == special_sentence:
            derived_key, salt = self.auth_manager.hash_password(new_password)
            self.db_manager.execute_query(
                """
                UPDATE users SET password_hash = ?, salt = ? WHERE id = ?
                """,
                (derived_key, salt, user[0]),
            )
            messagebox.showinfo("Success", "Password reset successfully!")
            self.master.destroy()
        else:
            messagebox.showerror("Error", "Invalid username or special sentence")


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
        self.start_auto_logout_timer()

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
        self.tree = ttk.Treeview(self.retrieve_password_tab, columns=("Service",), show="headings")
        self.tree.heading("Service", text="Service")
        self.tree.bind("<Double-1>", self.retrieve_password)  # Bind double-click event
        self.tree.grid(column=0, row=0, columnspan=2, sticky="nsew", pady=5)
        self.retrieve_result = ttk.Label(self.retrieve_password_tab, text="", font=("Arial", 12))
        self.retrieve_result.grid(column=0, row=1, columnspan=2, pady=10)
        # Populate the treeview with stored services
        self.populate_password_list()

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

    def retrieve_password(self, event=None):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a service")
            return

        service = self.tree.item(selected_item, "values")[0]
        results = self.db_manager.execute_query(
            """
            SELECT username, password, iv FROM passwords
            WHERE user_id = ? AND service = ?
            """,
            (self.user[0], service),
        ).fetchall()

        if results:
            credentials = "\n\n".join(
                [
                    f"Username: {username}\nPassword: {self.encryption_manager.decrypt_password(encrypted_password, iv, base64.urlsafe_b64decode(self.user[1]))}"
                    for username, encrypted_password, iv in results
                ]
            )
            self.retrieve_result.config(text=credentials)
        else:
            messagebox.showerror("Error", "No password found for this service")

    def logout(self):
        if hasattr(self, "auto_logout_timer"):
            self.master.after_cancel(self.auto_logout_timer)
        self.master.destroy()
        
    def start_auto_logout_timer(self):
        self.auto_logout_timer = self.master.after(300000, self.auto_logout)  # 300,000 ms = 5 minutes
        
    def auto_logout(self):
        messagebox.showinfo("Session Expired", "Your session has expired. Logging out.")
        self.logout()

    def populate_password_list(self):
        self.tree.delete(*self.tree.get_children())  # Clear existing entries
        services = self.db_manager.execute_query(
            "SELECT DISTINCT service FROM passwords WHERE user_id = ?", (self.user[0],)
        ).fetchall()
        for (service,) in services:
            self.tree.insert("", "end", values=(service,))


class PasswordManagerApp:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.auth_manager = AuthManager()
        self.encryption_manager = EncryptionManager()

        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.geometry("1080x720")
        self.root.resizable(True, True)

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
