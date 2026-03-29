import smtplib, time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GATEWAY_HOST = 'localhost'
GATEWAY_PORT = 2525

test_emails = [
    {
        'name': '🔴 PHISHING — Credential Reset Scam',
        'from': 'support@micr0soft-login.com',
        'to': 'user@company.com',
        'subject': 'Password Expired — Reset Immediately',
        'body': 'Your password has expired.\nReset now: http://microsoft-reset.secure-login.ru\nFailure to act will lock your account.',
        'reply_to': 'reset@evil.com',
    },
    {
        'name': '🔴 PHISHING — Fake Banking Alert',
        'from': 'alerts@hdfc-secure.net',
        'to': 'customer@bank.com',
        'subject': 'Suspicious Transaction Detected',
        'body': 'We detected unusual activity.\nVerify here: http://hdfc-alerts.verify-user.co\nLogin to secure your account.',
        'reply_to': 'fraud@attacker.com',
    },
    {
        'name': '🔴 PHISHING — Office365 Login',
        'from': 'admin@office365-security.org',
        'to': 'employee@company.com',
        'subject': 'Mailbox Storage Full',
        'body': 'Your mailbox is full.\nUpgrade now: http://office365-upgrade.fake-domain.ru\nLogin required.',
        'reply_to': 'admin@fake.com',
    },
    {
        'name': '🔴 PHISHING — DHL Delivery Scam',
        'from': 'noreply@dhl-delivery.net',
        'to': 'user@company.com',
        'subject': 'Package Delivery Failed',
        'body': 'Your shipment is on hold.\nTrack here: http://dhl-tracking.fake-site.ru\nPay ₹150 to release package.',
        'reply_to': 'support@fake.com',
    },
    {
        'name': '🔴 PHISHING — Job Offer Scam',
        'from': 'hr@tcs-careers.net',
        'to': 'candidate@gmail.com',
        'subject': 'Job Offer Letter — Immediate Joining',
        'body': 'Congratulations!\nDownload offer letter: http://tcs-offer-letter.fake.ru\nPay ₹2000 processing fee.',
        'reply_to': 'hr.fake@gmail.com',
    },
    {
        'name': '🔴 PHISHING — UPI KYC Update',
        'from': 'kyc@paytm-verification.org',
        'to': 'user@paytm.com',
        'subject': 'KYC Expired — Update Now',
        'body': 'Your Paytm KYC expired.\nUpdate here: http://paytm-kyc-update.fake.ru\nAccount will be blocked otherwise.',
        'reply_to': 'support@fake.com',
    },
    {
        'name': '🔴 PHISHING — Crypto Giveaway',
        'from': 'elonmusk@tesla-event.net',
        'to': 'user@gmail.com',
        'subject': 'Win 1 BTC — Limited Offer',
        'body': 'Send 0.1 BTC and receive 1 BTC back!\nWallet: 1FakeBTCAddressXYZ\nHurry, limited time!',
        'reply_to': 'crypto@scam.com',
    },
    {
        'name': '🔴 PHISHING — Fake IT Support',
        'from': 'it-helpdesk@company-support.org',
        'to': 'employee@company.com',
        'subject': 'VPN Access Issue — Re-login Required',
        'body': 'VPN access issue detected.\nLogin here: http://company-vpn-fix.fake.ru\nRe-enter credentials.',
        'reply_to': 'it@fake.com',
    },
    {
        'name': '🟢 LEGIT — Company Meeting Reminder',
        'from': 'noreply@company.com',
        'to': 'team@company.com',
        'subject': 'Reminder: Weekly Sync Meeting',
        'body': 'Reminder for weekly sync at 10 AM.\nJoin via official Teams link.\n\nThanks,\nAdmin',
        'reply_to': '',
    },
    {
        'name': '🟢 LEGIT — Amazon Order Confirmation',
        'from': 'orders@amazon.in',
        'to': 'user@gmail.com',
        'subject': 'Your Amazon Order #123-4567890-1234567',
        'body': 'Your order has been placed successfully.\nTrack here: https://amazon.in/orders\n\nThank you for shopping with us.',
        'reply_to': '',
    },
]

print('='*65)
print('  AegisAI SMTP Fraud Gateway — Live Demo')
print('  Intercepting emails at port 2525')
print('='*65)

for test in test_emails:
    msg = MIMEMultipart()
    msg['From'] = test['from']
    msg['To'] = test['to']
    msg['Subject'] = test['subject']
    if test['reply_to']:
        msg['Reply-To'] = test['reply_to']
    msg.attach(MIMEText(test['body'], 'plain'))

    try:
        with smtplib.SMTP(GATEWAY_HOST, GATEWAY_PORT, timeout=30) as s:
            s.send_message(msg)
        result = '✅ ALLOWED  → appears in Mailbox as LOW/MEDIUM'
    except smtplib.SMTPDataError as e:
        code = e.smtp_error.decode()
        result = f'🚫 BLOCKED  → {code[:60]}'
    except Exception as e:
        result = f'ERROR: {e}'

    name    = test['name']
    sender  = test['from']
    subject = test['subject']
    print(f'\n{name}')
    print(f'  From:    {sender}')
    print(f'  Subject: {subject}')
    print(f'  Result:  {result}')
    time.sleep(1)

print('\n' + '='*65)
print('  Check results at:')
print('  Mailbox UI  → http://localhost')
print('  Gateway log → http://localhost/api/smtp-gateway/decisions')
print('  MailHog     → http://localhost:8025  (clean emails)')
print('='*65)
