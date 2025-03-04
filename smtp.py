import smtplib
import random
import string
import tkinter as tk
from tkinter import messagebox, ttk
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SENDER_EMAIL = "sgp.noreplydce@gmail.com"
SENDER_PASSWORD = "haub ylen jpof ypse"


def generate_verification_code():
    return "".join(random.choices(string.digits, k=6))


def send_verification_email(receiver_email, code):
    subject = "Your Two Factor Verification Code"
    body = f"Your verification code is: {code}"

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email failed to send: {e}")
        return False


class EmailVerificationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Verification")
        self.root.geometry("400x400")
        self.root.resizable(False, False)

        # Set style
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 12))
        self.style.configure("TEntry", font=("Arial", 12))
        self.style.configure("TButton", font=("Arial", 12, "bold"))

        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20 20 20 20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.verification_code = None

        # App title
        ttk.Label(
            self.main_frame,
            text="Email Verification System",
            font=("Arial", 16, "bold"),
        ).pack(pady=(0, 20))

        # Email frame
        self.email_frame = ttk.Frame(self.main_frame)
        self.email_frame.pack(fill=tk.X, pady=10)

        ttk.Label(self.email_frame, text="Email Address:").pack(
            anchor=tk.W, pady=(0, 5)
        )

        self.email_entry = ttk.Entry(self.email_frame, width=40)
        self.email_entry.pack(fill=tk.X)

        self.send_button = ttk.Button(
            self.email_frame, text="Send Verification Code", command=self.send_code
        )
        self.send_button.pack(anchor=tk.E, pady=(10, 0))

        # Code verification frame
        self.code_frame = ttk.Frame(self.main_frame)
        self.code_frame.pack(fill=tk.X, pady=20)

        ttk.Label(self.code_frame, text="Verification Code:").pack(
            anchor=tk.W, pady=(0, 5)
        )

        self.code_entry = ttk.Entry(self.code_frame, width=10, font=("Arial", 14))
        self.code_entry.pack(pady=5)

        self.verify_button = ttk.Button(
            self.code_frame, text="Verify Code", command=self.verify_code
        )
        self.verify_button.pack(pady=(10, 0))

        # Status indicator
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(
            self.main_frame, textvariable=self.status_var, foreground="gray"
        )
        self.status_label.pack(pady=20)
        self.status_var.set("Enter your email and request a verification code")

    def send_code(self):
        email = self.email_entry.get()
        if not email:
            messagebox.showerror("Error", "Please enter an email!")
            return

        self.status_var.set("Sending verification code...")
        self.root.update_idletasks()

        self.verification_code = generate_verification_code()
        success = send_verification_email(email, self.verification_code)

        if success:
            messagebox.showinfo("Success", "Verification code sent to your email!")
            self.status_var.set("Code sent! Please check your email")
            self.code_entry.focus()
        else:
            messagebox.showerror("Error", "Failed to send email")
            self.status_var.set("Failed to send code. Please try again.")

    def verify_code(self):
        user_code = self.code_entry.get()
        if user_code == self.verification_code:
            messagebox.showinfo("Success", "Email verified successfully!")
            self.status_var.set("Email verified successfully!")
        else:
            messagebox.showerror("Error", "Invalid verification code!")
            self.status_var.set("Invalid code. Please try again.")


if __name__ == "__main__":
    root = tk.Tk()
    app = EmailVerificationApp(root)
    root.mainloop()
