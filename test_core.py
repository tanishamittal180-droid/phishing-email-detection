from backend.services.analyzers import analyze_sender, analyze_content, analyze_url, analyze_attachment
from backend.services.risk_engine import calculate_score

def result(sender='training@example.org',subject='Workshop reminder',body='Hello team. The workshop starts tomorrow.',url=None,attachment=''):
    s=analyze_sender(sender); c=analyze_content(subject,body); u=[analyze_url(url)] if url else []; a=analyze_attachment(attachment); return calculate_score(s,c,u,a)

def test_legitimate_low(): assert result()['risk_score']<=20

def test_urgent_credential(): assert result('security-alert@account-check.invalid.test','URGENT verify password','Act now and verify your password at http://198.51.100.10/verify-account','http://198.51.100.10/verify-account') ['risk_score']>40

def test_raw_ip(): assert analyze_url('http://198.51.100.10/verify-account')['score']>=20

def test_https_not_zero(): assert analyze_url('https://example.org/resources')['score']>=0

def test_excess_subdomains(): assert any('subdomains' in f[0].lower() for f in analyze_url('http://a.b.c.example.org/login')['findings'])

def test_shortener(): assert analyze_url('https://bit.ly/demo')['score']>=15

def test_attachment_exe(): assert analyze_attachment('invoice.exe')['score']>=30

def test_double_extension(): assert analyze_attachment('invoice.pdf.exe')['score']>=30

def test_generic_greeting(): assert analyze_content('Hello','Dear customer, please review this.')['generic_greeting']

def test_financial(): assert analyze_content('Invoice due','Outstanding payment is due.')['financial_keyword_count']>0

def test_threat(): assert analyze_content('Final warning','Your account will be suspended.')['threat_keyword_count']>0

def test_personal_info(): assert analyze_content('Details','Confirm your personal details.')['findings']

def test_empty_sender(): assert analyze_sender('')['score']>=20

def test_uppercase(): assert analyze_content('URGENT NOW!!!','THIS IS IMPORTANT!!!') ['uppercase_ratio']>0

def test_no_url(): assert result()['risk_score']<=20

def test_high_risk_combo(): r=result('security-alert@account-check.invalid.test','URGENT: Verify your account','Immediately verify your password and OTP or your account will be suspended. http://198.51.100.10/verify-account','http://198.51.100.10/verify-account','invoice.pdf.exe'); assert r['risk_score']>=70

def test_score_cap(): r=result('bad','URGENT password payment suspended prize','! '*100,'http://198.51.100.10/verify','invoice.pdf.exe'); assert r['risk_score']<=100

def test_classification_exists(): assert result()['classification']

def test_recommendations(): assert len(result()['recommendations'])>=3

def test_url_keyword(): assert any('keyword' in f[0].lower() for f in analyze_url('https://example.org/verify-account')['findings'])
def test_url_length(): assert any('long url' in f[0].lower() for f in analyze_url('https://example.org/'+'a'*120)['findings'])
def test_archive_attachment(): assert analyze_attachment('documents.zip')['score']>=10
def test_empty_attachment(): assert analyze_attachment('')['score']==0
def test_body_length_feature(): assert analyze_content('x','hello')['body_length']==5
def test_subject_length_feature(): assert analyze_content('hello','x')['subject_length']==5
def test_url_scheme(): assert analyze_url('https://example.org')['scheme']=='https'
