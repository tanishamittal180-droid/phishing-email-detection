import csv, random
from pathlib import Path
random.seed(42)
OUT=Path(__file__).parent/'phishing_email_dataset.csv'
legit=[('training@example.org','Cybersecurity Workshop Reminder','Hello team, this is a reminder that the defensive cybersecurity workshop starts tomorrow at 10:00. No action is required.'),('hr@example.com','HR Project Update','Your project documentation has been received. Please review the attached agenda before the next meeting.'),('library@example.org','Library Newsletter','This month\'s library newsletter includes new books, opening hours, and upcoming study events.'),('shop.example.net','Order Confirmation','Your fictional-store order has been recorded. This message contains no payment or credential request.'),('bank.example.org','Monthly Statement Notice','Your fictional bank statement is available in the official application. You can review it when convenient.')]
phish=[('security-alert@account-check.invalid.test','URGENT: Verify Your Account Immediately','Your account will be suspended today. Verify your password and security code immediately using the link below.'),('billing@invoice-check.invalid.test','FINAL NOTICE: Invoice Payment Required','Outstanding invoice payment is due immediately. Confirm your account details to avoid suspension.'),('rewards@prize.invalid.test','Congratulations! You Have Won','You have won a reward. Claim your prize immediately by verifying your account information.'),('delivery@parcel.invalid.test','Delivery Verification Required','Your delivery is waiting. Confirm personal details and payment information within 24 hours.'),('executive@request.invalid.test','Urgent Confidential Request','Please process this unusual payment request immediately and keep the request confidential.')]
rows=[]
for i in range(600):
    label=random.choice(['LEGITIMATE','PHISHING']); src=random.choice(legit if label=='LEGITIMATE' else phish)
    sender,subject,body=src; urls=''
    if label=='PHISHING': urls=random.choice(['http://198.51.100.10/verify-account','http://198.51.100.20/invoice-payment','http://198.51.100.30/confirm-login'])
    elif random.random()<.25: urls='https://example.org/resources'
    attachment=''
    if label=='PHISHING' and random.random()<.3: attachment=random.choice(['invoice.pdf.exe','document.js','statement.zip'])
    rows.append([f'E{100000+i}',sender,sender.split('@')[-1],subject,body,urls,attachment,label])
with OUT.open('w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['email_id','sender','sender_domain','subject','body','urls','attachment_name','label']); w.writerows(rows)
print(f'Generated {len(rows)} records -> {OUT}')
