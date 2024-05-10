import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

class EmailNotifier:
    def __init__(self, sender_email, sender_password, receiver_email, smtp_server, smtp_port):
        # Constructor for EmailNotifier class. Initializes with sender and receiver email details,
        # as well as SMTP server settings.
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.receiver_email = receiver_email
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def send_email(self, subject, message, attachment_path=None):
        # Sends an email with an optional attachment.
        # If an attachment path is provided, the file at that path is attached to the email.

        # Logging the email sending attempt to the console for debugging purposes.
        print(f"Sending email:\nSubject: {subject}\nMessage: {message}")

        # Creating a MIME multipart message to compose the email.
        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email
        msg['Subject'] = subject
        
        # Attaching the main email message body.
        msg.attach(MIMEText(message, 'plain'))

        # If an attachment path is provided, process and attach the file.
        if attachment_path: 
            with open(attachment_path, "rb") as attachment: 
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())

            # Encoding the attachment in base64 to prepare it for email transmission.
            encoders.encode_base64(part)
            
            # Adding a header to the attachment specifying the filename.
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={attachment_path.split('/')[-1]}",
            )
            msg.attach(part)

        # Attempting to connect to the SMTP server and send the email.
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.ehlo()  # Greet the server. Optional, but can help identify supported features.
                server.starttls()  # Upgrade the connection to a secure TLS connection.
                server.ehlo()  # Re-greet the server over the secure connection.
                server.login(self.sender_email, self.sender_password)  # Log in to the SMTP server.
                server.sendmail(self.sender_email, self.receiver_email, msg.as_string())  # Send the email.
            print("Email sent successfully.")
        except Exception as e:
            print(f"Failed to send email. Error: {e}")
"""
The EmailNotifier class simplifies the process of sending emails from Python scripts. 
It encapsulates the details of composing and sending an email, including handling attachments.
By providing the SMTP server details and credentials, users can send emails to one or more recipients,
making it useful for notifications, alerts, and automated email tasks.
"""