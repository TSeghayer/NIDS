import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

class EmailNotifier:
    """
    A class to manage the sending of emails. It handles setting up SMTP connections, composing emails,
    attaching files, and sending them securely using SMTP.
    """

    def __init__(self, sender_email, sender_password, receiver_email, smtp_server, smtp_port):
        """
        Constructor to initialize the EmailNotifier with email sending and receiving details,
        along with SMTP server configuration.

        Parameters:
            sender_email (str): The email address from which the email will be sent.
            sender_password (str): The password for the sender's email account for SMTP authentication.
            receiver_email (str): The email address of the recipient.
            smtp_server (str): The address of the SMTP server used to send emails.
            smtp_port (int): The port on which the SMTP server is listening.
        """
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.receiver_email = receiver_email
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def send_email(self, subject, message, attachment_path=None):
        """
        Sends an email with the specified subject and message, and optionally includes an attachment.

        Parameters:
            subject (str): The subject line of the email.
            message (str): The body of the email.
            attachment_path (str, optional): The file system path to a file to attach to the email.

        Logs:
            Prints details of the email sending attempt for debugging purposes.
        """
        print(f"Sending email:\nSubject: {subject}\nMessage: {message}")

        # Create a Multipart message to enable both plain text and attachments.
        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email
        msg['Subject'] = subject
        
        # Attach the main text content of the email.
        msg.attach(MIMEText(message, 'plain'))

        # Process and attach the file if an attachment_path is provided.
        if attachment_path:
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())  # Load file content to the MIMEBase object.

            encoders.encode_base64(part)  # Encode file content in base64 for email transmission.

            # Specify the filename for the attachment.
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={attachment_path.split('/')[-1]}",
            )
            msg.attach(part)  # Attach the file to the message.

        # Connect to the SMTP server and send the email.
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.ehlo()  # Can be useful for identifying supported server features.
                server.starttls()  # Secure the SMTP connection with TLS.
                server.ehlo()  # Reidentify the client to the server after starting TLS.
                server.login(self.sender_email, self.sender_password)  # Log in to the SMTP server.
                server.sendmail(self.sender_email, self.receiver_email, msg.as_string())  # Send the composed email.
            print("Email sent successfully.")
        except Exception as e:
            print(f"Failed to send email. Error: {e}")


"""
The EmailNotifier class simplifies the process of sending emails from Python scripts. 
It encapsulates the details of composing and sending an email, including handling attachments.
By providing the SMTP server details and credentials, users can send emails to one or more recipients,
making it useful for notifications, alerts, and automated email tasks.
"""