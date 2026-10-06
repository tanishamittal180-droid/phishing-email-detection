import re, ipaddress
from urllib.parse import urlparse

URGENCY = ["urgent","immediately","act now","as soon as possible","final warning","today","within 24 hours","action required"]
CREDENTIAL = ["password","passcode","otp","one-time password","verify your account","login","sign in","credentials","security code"]
FINANCIAL = ["invoice","payment","wire transfer","bank","refund","outstanding","payment due","gift card","transaction"]
THREAT = ["suspended","suspension","terminated","blocked","legal action","penalty","will be closed","final notice"]
REWARD = ["you have won","winner","prize","reward","claim your bonus","congratulations"]
PERSONAL = ["personal details","date of birth","address","social security","identity","confirm your details"]
URL_WORDS = ["verify","login","signin","secure","account","password","update","confirm","payment","invoice"]
SHORTENERS = {"bit.ly","tinyurl.com","t.co","is.gd","ow.ly","cutt.ly","shorturl.at"}
RISKY_EXT = {".exe",".scr",".bat",".cmd",".js",".vbs",".ps1",".jar",".msi",".com"}
ARCHIVE_EXT = {".zip",".rar",".7z",".iso"}


def _count(text, terms):
    t = (text or "").lower()
    return sum(t.count(x) for x in terms)


def extract_urls(text):
    return re.findall(r"https?://[^\s<>\]\[\"']+", text or "", flags=re.I)


def domain_from_sender(sender):
    m = re.search(r"@([^\s>]+)", sender or "")
    return m.group(1).strip().lower() if m else ""


def analyze_sender(sender, display_name=""):
    score, findings = 0, []
    domain = domain_from_sender(sender)
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender or ""):
        score += 20; findings.append(("Invalid sender format", "Sender address does not match a normal email format.", "medium"))
    if domain:
        if len(domain) > 45:
            score += 8; findings.append(("Long sender domain", "The domain is unusually long and deserves verification.", "low"))
        labels = domain.split(".")
        if len(labels) >= 4:
            score += 8; findings.append(("Excessive subdomains", "The sender uses several domain levels; this is a review signal, not proof of phishing.", "medium"))
        if re.search(r"[^a-z0-9.\-]", domain):
            score += 8; findings.append(("Unusual domain characters", "The domain contains unusual characters.", "medium"))
        if re.search(r"(secure|verify|support|account|alert|billing)[0-9\-]", domain):
            score += 10; findings.append(("Security-themed domain pattern", "The domain name uses security/account language that should be verified independently.", "medium"))
    if display_name and domain:
        name_words = re.sub(r"[^a-z0-9 ]", "", display_name.lower()).split()
        if name_words and not any(w in domain for w in name_words if len(w) > 3):
            score += 5; findings.append(("Display-name/domain mismatch", "The display name does not obviously correspond to the sender domain.", "low"))
    return {"score": min(score,100), "domain": domain, "findings": findings}


def analyze_content(subject, body):
    text = f"{subject or ''} {body or ''}"
    lower = text.lower(); findings=[]
    groups = [("Urgency", URGENCY, "Urgent or deadline pressure can reduce careful verification."),
              ("Credential request", CREDENTIAL, "The message references credentials, login, passwords, OTPs, or verification."),
              ("Financial pressure", FINANCIAL, "Financial language can be used to pressure recipients into unsafe actions."),
              ("Threat/fear language", THREAT, "Threats or account consequences can be used as social-engineering pressure."),
              ("Reward claim", REWARD, "Unexpected prizes or rewards can be used as lures."),
              ("Personal-information request", PERSONAL, "Requests for personal information require independent verification.")]
    for label, words, explanation in groups:
        c=_count(lower,words)
        if c: findings.append((label, explanation, "high" if label in {"Credential request","Threat/fear language"} else "medium", c))
    generic = bool(re.search(r"\b(dear customer|dear user|dear member|dear valued customer|hello customer)\b", lower))
    if generic: findings.append(("Generic greeting", "The message uses a broad greeting rather than an identifiable recipient.", "low", 1))
    exclamations=(text.count("!"));
    uppercase_letters=sum(c.isupper() for c in text if c.isalpha()); letters=sum(c.isalpha() for c in text)
    upper_ratio=uppercase_letters/letters if letters else 0
    if exclamations >= 3: findings.append(("Excessive exclamation marks", "Heavy punctuation may indicate attention or urgency pressure.", "low", exclamations))
    if upper_ratio > .35 and letters > 30: findings.append(("High uppercase ratio", "A high proportion of uppercase text can be a presentation warning sign.", "low", round(upper_ratio,2)))
    return {"findings":findings,"urgent_keyword_count":_count(lower,URGENCY),"credential_keyword_count":_count(lower,CREDENTIAL),"financial_keyword_count":_count(lower,FINANCIAL),"threat_keyword_count":_count(lower,THREAT),"generic_greeting":generic,"exclamation_count":exclamations,"uppercase_ratio":round(upper_ratio,3),"body_length":len(body or ""),"subject_length":len(subject or "")}


def analyze_url(url):
    findings=[]; score=0
    try:
        p=urlparse(url.strip()); host=p.hostname or ""; scheme=p.scheme.lower()
        if scheme != "https": score+=10; findings.append(("Non-HTTPS URL","The link is not using HTTPS. HTTPS alone would not prove trustworthiness.","medium"))
        try: ipaddress.ip_address(host); score+=20; findings.append(("Raw IP address","The hostname is a literal IP address, which is a useful review signal.","high"))
        except ValueError: pass
        if len(url)>100: score+=8; findings.append(("Long URL","The URL is unusually long.","low"))
        labels=host.split('.') if host else []
        if len(labels)>=4: score+=8; findings.append(("Excessive subdomains","Multiple subdomains can make a destination harder to recognize.","medium"))
        if host.lower() in SHORTENERS: score+=15; findings.append(("URL shortener","Shortened links obscure the final destination.","medium"))
        for word in URL_WORDS:
            if word in (p.path+"?"+p.query).lower(): score+=5; findings.append(("Suspicious URL keyword",f"The URL contains the keyword '{word}'.","medium")); break
        if re.search(r"[%@]|//.*//", url): score+=6; findings.append(("Unusual URL structure","The URL contains characters or structure worth verifying carefully.","low"))
        return {"url":url,"scheme":scheme,"hostname":host,"path":p.path,"query":p.query,"score":min(score,100),"findings":findings}
    except Exception:
        return {"url":url,"scheme":"","hostname":"","path":"","query":"","score":25,"findings":[("Malformed URL","The URL could not be parsed normally.","medium")]}


def analyze_attachment(filename):
    if not filename: return {"score":0,"findings":[]}
    name=filename.lower(); findings=[]; score=0
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|bat|cmd|js|vbs|ps1)$", name):
        score+=30; findings.append(("Double extension","The filename disguises an executable/script after a document-like extension.","high"))
    ext='.'+name.rsplit('.',1)[-1] if '.' in name else ''
    if ext in RISKY_EXT: score+=30; findings.append(("Executable/script extension","Executable or script attachments should not be opened unexpectedly.","high"))
    elif ext in ARCHIVE_EXT: score+=10; findings.append(("Archive attachment","Archives can contain files whose type is hidden until extraction.","medium"))
    return {"score":min(score,100),"findings":findings}
