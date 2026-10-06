def calculate_score(sender, content, urls, attachment):
    contributions=[]
    s=0
    def add(points,label,reason):
        nonlocal s
        if points: s+=points; contributions.append({"indicator":label,"points":points,"description":reason,"severity":"high" if points>=20 else "medium" if points>=10 else "low"})
    add(min(sender["score"],15),"Suspicious sender pattern","Sender analysis produced review signals.")
    if content["urgent_keyword_count"]: add(10,"Urgency","Urgency/deadline language detected.")
    if content["credential_keyword_count"]: add(20,"Credential request","Credential or account-verification language detected.")
    if content["financial_keyword_count"]: add(8,"Financial pressure","Financial/payment language detected.")
    if content["threat_keyword_count"]: add(10,"Threat/fear language","Threat or suspension language detected.")
    if content["generic_greeting"]: add(5,"Generic greeting","Broad greeting detected.")
    if urls:
        us=sum(u["score"] for u in urls); add(min(20, round(us/2)),"Suspicious URL","One or more URLs have static risk indicators.")
    add(min(25,attachment["score"]),"Suspicious attachment","Attachment filename has risk indicators.")
    score=min(100,s)
    classification="LOW RISK" if score<=20 else "MODERATE RISK" if score<=40 else "SUSPICIOUS" if score<=70 else "HIGH RISK / LIKELY PHISHING"
    actions=["Do not click links or open unexpected attachments.","Verify the sender through a trusted channel.","Use the organization’s official website/app directly rather than email links.","Report suspicious messages to the security team when appropriate."]
    return {"risk_score":score,"classification":classification,"contributions":contributions,"recommendations":actions}
