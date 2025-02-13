import smtplib
import random
import string
import tkinter as tk
from tkinter import messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SENDER_EMAIL = "sgp.noreplydce@gmail.com"
SENDER_PASSWORD = "haub ylen jpof ypse"


def generate_verification_code():
    return "".join(random.choices(string.digits, k=6))


def send_verification_email(receiver_email, code):
    subject = "Your PyLock Password Manager Verification Code"
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

        self.verification_code = None 

        tk.Label(root, text="Enter your email:").pack(pady=5)
        self.email_entry = tk.Entry(root, width=30)
        self.email_entry.pack(pady=5)

        tk.Button(root, text="Send Code", command=self.send_code).pack(pady=5)

        tk.Label(root, text="Enter verification code:").pack(pady=5)
        self.code_entry = tk.Entry(root, width=10)
        self.code_entry.pack(pady=5)

        tk.Button(root, text="Verify", command=self.verify_code).pack(pady=5)

    def send_code(self):
        email = self.email_entry.get()
        if not email:
            messagebox.showerror("Error", "Please enter an email!")
            return

        self.verification_code = generate_verification_code()
        success = send_verification_email(email, self.verification_code)

        if success:
            messagebox.showinfo("Success", "Verification code sent to your email!")
        else:
            messagebox.showerror("Error", "Failed to send email")

    def verify_code(self):
        user_code = self.code_entry.get()
        if user_code == self.verification_code:
            messagebox.showinfo("Success", "Email verified successfully!")
        else:
            messagebox.showerror("Error", "Invalid verification code!")

root = tk.Tk()
app = EmailVerificationApp(root)
root.mainloop()