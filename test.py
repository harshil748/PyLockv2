import imaplib
import email
from email.header import decode_header

# Email credentials
IMAP_SERVER = "imap.gmail.com"  # Change for other providers (e.g., Outlook: "imap-mail.outlook.com")
EMAIL_ACCOUNT = "sgp.noreplydce@gmail.com"
EMAIL_PASSWORD = "zppi jfjy xxvb wftm"  # Use an app password if using Gmail


def get_latest_otp_email():
    try:
        # Connect to the IMAP server
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        mail.select("inbox")  # Select inbox folder

        # Search for unread OTP emails (modify the filter as needed)
        status, messages = mail.search(None, '(UNSEEN SUBJECT "Your OTP")')
        email_ids = messages[0].split()

        if not email_ids:
            print("No new OTP emails found.")
            return None

        # Fetch the latest email
        latest_email_id = email_ids[-1]
        status, msg_data = mail.fetch(latest_email_id, "(RFC822)")

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                subject = subject.decode(encoding) if encoding else subject

                print(f"Email Subject: {subject}")

                # Extract email content
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == "text/plain":  # Extract plain text content
                            otp_body = part.get_payload(decode=True).decode()
                            print(f"OTP Email Content:\n{otp_body}")
                            return otp_body
                else:
                    otp_body = msg.get_payload(decode=True).decode()
                    print(f"OTP Email Content:\n{otp_body}")
                    return otp_body

        mail.logout()
    except Exception as e:
        print(f"Error: {e}")


# Run the function
get_latest_otp_email()
