import smtplib
from email.message import EmailMessage

def send_test_email():
    msg = EmailMessage()
    msg.set_content("""Dear user,
    
Please review the attached invoice and verify your account by clicking the link below:
http://secure-update-now.com/login

Thank you,
Billing Department
""")
    
    msg['Subject'] = 'Urgent: Unpaid Invoice Action Required'
    msg['From'] = 'billing@paypal-update-secure.com'
    msg['To'] = 'employee@company.com'

    print("Sending test email to the SMTP Fraud Gateway (localhost:2525)...")
    
    try:
        with smtplib.SMTP('localhost', 2525) as server:
            server.send_message(msg)
        print("[SUCCESS] Test email sent and accepted by the gateway!")
        print("-> Now check the Mailbox UI at http://localhost:5173 to see the scan results.")
    except smtplib.SMTPDataError as e:
        print(f"[BLOCKED] The SMTP Fraud Gateway successfully intercepted and rejected the email!")
        print(f"Reason from server: {e.smtp_error.decode('utf-8')}")
        print("This means the pipeline is working perfectly!")
    except Exception as e:
        print(f"[ERROR] Failed to connect or send email: {e}")
        print("Ensure the smtp-fraud-gateway docker container is running.")

if __name__ == "__main__":
    send_test_email()
