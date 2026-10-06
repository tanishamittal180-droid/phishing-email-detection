from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pathlib import Path
from .services.analyzers import *
from .services.risk_engine import calculate_score
from .database import init_db, save_analysis, conn
import re

BASE=Path(__file__).resolve().parents[1]
app=FastAPI(title="Phishing Email Detection & Awareness Dashboard",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])
init_db()

class EmailInput(BaseModel):
    sender:str=Field(default="",max_length=320); display_name:str=Field(default="",max_length=200); subject:str=Field(default="",max_length=500); body:str=Field(default="",max_length=50000); attachment_name:str=Field(default="",max_length=255); store_history:bool=True

@app.get("/api/health")
def health(): return {"status":"ok","service":"phishing-dashboard"}

@app.post("/api/analyze")
def analyze(e:EmailInput):
    if not e.subject.strip() and not e.body.strip(): raise HTTPException(400,"Subject or body is required")
    urls=[analyze_url(u) for u in extract_urls(e.body)]
    sender=analyze_sender(e.sender,e.display_name); content=analyze_content(e.subject,e.body); attachment=analyze_attachment(e.attachment_name)
    risk=calculate_score(sender,content,urls,attachment)
    result={"input":{"sender":e.sender,"subject":e.subject,"attachment_name":e.attachment_name},"sender":sender,"content":content,"attachment":attachment,"urls":urls,**risk}
    if e.store_history: result["analysis_id"]=save_analysis(result)
    return result

@app.post("/api/analyze/url")
def analyze_one_url(payload:dict):
    url=str(payload.get("url","")).strip()
    if not url: raise HTTPException(400,"URL is required")
    return analyze_url(url)

@app.post("/api/analyze/file")
async def analyze_file(file:UploadFile=File(...)):
    if not file.filename.lower().endswith((".txt",".eml")): raise HTTPException(400,"Only .txt and .eml files are allowed")
    raw=await file.read(512000)
    text=raw.decode("utf-8",errors="replace")
    subject=(re.search(r"^Subject:\s*(.*)$",text,re.I|re.M) or ["",""])[1]
    sender=(re.search(r"^(?:From):\s*(.*)$",text,re.I|re.M) or ["",""])[1]
    body=text.split("\n\n",1)[1] if "\n\n" in text else text
    return analyze(EmailInput(sender=sender,subject=subject,body=body,store_history=True))

@app.get("/api/analyses")
def analyses(limit:int=50,classification:str="",q:str=""):
    c=conn(); sql="SELECT * FROM analyses WHERE 1=1"; params=[]
    if classification: sql+=" AND classification=?"; params.append(classification)
    if q: sql+=" AND (subject LIKE ? OR sender_domain LIKE ?)"; params += [f"%{q}%",f"%{q}%"]
    sql+=" ORDER BY analysis_id DESC LIMIT ?"; params.append(min(max(limit,1),200)); rows=[dict(x) for x in c.execute(sql,params).fetchall()]; c.close(); return {"items":rows}

@app.get("/api/analyses/{aid}")
def analysis_detail(aid:int):
    c=conn(); a=c.execute("SELECT * FROM analyses WHERE analysis_id=?",(aid,)).fetchone()
    if not a: raise HTTPException(404,"Analysis not found")
    out=dict(a); out['indicators']=[dict(x) for x in c.execute("SELECT * FROM indicators WHERE analysis_id=?",(aid,)).fetchall()]; out['urls']=[dict(x) for x in c.execute("SELECT * FROM url_analyses WHERE analysis_id=?",(aid,)).fetchall()]; c.close(); return out

@app.delete("/api/analyses/{aid}")
def delete_analysis(aid:int):
    c=conn(); c.execute("DELETE FROM indicators WHERE analysis_id=?",(aid,)); c.execute("DELETE FROM url_analyses WHERE analysis_id=?",(aid,)); cur=c.execute("DELETE FROM analyses WHERE analysis_id=?",(aid,)); c.commit(); c.close(); return {"deleted":cur.rowcount>0}

@app.get("/api/dashboard/stats")
def stats():
    c=conn(); total=c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]; high=c.execute("SELECT COUNT(*) FROM analyses WHERE classification LIKE 'HIGH%'").fetchone()[0]; susp=c.execute("SELECT COUNT(*) FROM analyses WHERE classification='SUSPICIOUS'").fetchone()[0]; low=c.execute("SELECT COUNT(*) FROM analyses WHERE classification IN ('LOW RISK','MODERATE RISK')").fetchone()[0]; avg=c.execute("SELECT COALESCE(AVG(risk_score),0) FROM analyses").fetchone()[0]
    cls=[dict(x) for x in c.execute("SELECT classification,COUNT(*) count FROM analyses GROUP BY classification").fetchall()]
    inds=[dict(x) for x in c.execute("SELECT indicator_type name,COUNT(*) count FROM indicators GROUP BY indicator_type ORDER BY count DESC LIMIT 10").fetchall()]
    trend=[dict(x) for x in c.execute("SELECT date(created_at) date,COUNT(*) total,SUM(CASE WHEN risk_score>70 THEN 1 ELSE 0 END) high FROM analyses GROUP BY date(created_at) ORDER BY date DESC LIMIT 14").fetchall()]; c.close()
    return {"total":total,"high_risk":high,"suspicious":susp,"low_risk":low,"average_score":round(avg,1),"classification":cls,"indicators":inds,"trend":list(reversed(trend))}

@app.get("/api/awareness")
def awareness():
    return {"lessons":[{"title":"Hover to Verify","text":"Inspect the destination before opening a link. HTTPS is useful for transport security but does not prove the sender or destination is trustworthy."},{"title":"Check the Sender","text":"Look beyond the display name. Verify the actual domain and use a trusted contact path when a request is unusual."},{"title":"Urgency Is a Signal","text":"Pressure to act immediately can interfere with careful review. Pause and verify independently."},{"title":"Protect Credentials","text":"Unexpected password, OTP, or login requests should be verified through the official application or website."},{"title":"Attachments Need Context","text":"Do not open unexpected executables or scripts. Confirm the sender and expected file through a trusted channel."},{"title":"Context Wins","text":"A single indicator does not prove phishing. Consider sender, content, links, attachments, and expected business context together."}],"checklist":["Verify sender domain","Read the URL before clicking","Pause when urgency is unusual","Never share passwords or OTPs by email","Treat unexpected attachments cautiously","Verify payment changes out-of-band","Report suspicious email according to policy"]}

app.mount("/",StaticFiles(directory=BASE/"frontend",html=True),name="frontend")
