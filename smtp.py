import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time

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


def main():
    print("Two-Factor Email Verification System")

    # Get email address from user
    email = input("\nEnter your email address: ")
    if not email:
        print("Error: Email address cannot be empty!")
        return

    print("\nSending verification code...")

    # Generate and send verification code
    verification_code = generate_verification_code()
    success = send_verification_email(email, verification_code)
    last_sent_time = time.time()

    if not success:
        print("Error: Failed to send email. Please try again.")
        return

    print("Success: Verification code sent to your email!")

    verified = False
    while not verified:
        # Get verification code from user
        print("\nPlease check your email for the verification code.")
        print(
            "Enter the verification code or 'r' to resend (can resend after 30 seconds):"
        )
        user_input = input("> ")

        if user_input.lower() == "r":
            current_time = time.time()
            time_elapsed = current_time - last_sent_time

            if time_elapsed < 30:
                print(
                    f"Please wait {int(30 - time_elapsed)} more seconds before requesting a new code."
                )
                continue

            print("\nResending verification code...")
            verification_code = generate_verification_code()
            success = send_verification_email(email, verification_code)
            last_sent_time = current_time

            if success:
                print("Success: New verification code sent to your email!")
            else:
                print("Error: Failed to send email. Please try again.")
        else:
            # Verify the code
            if user_input == verification_code:
                print("\nSuccess: Email verified successfully!")
                verified = True
            else:
                print(
                    "\nError: Invalid verification code. Try again or request a new code."
                )


if __name__ == "__main__":
    main()
