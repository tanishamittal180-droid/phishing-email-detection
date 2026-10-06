import sqlite3, json
from pathlib import Path
DB=Path(__file__).resolve().parents[1]/"database"/"phishing.db"

def conn():
    DB.parent.mkdir(exist_ok=True); c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=conn(); c.executescript('''CREATE TABLE IF NOT EXISTS analyses(analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,sender_domain TEXT,subject TEXT,risk_score INTEGER,classification TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS indicators(indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,analysis_id INTEGER,indicator_type TEXT,description TEXT,severity TEXT,points INTEGER,FOREIGN KEY(analysis_id) REFERENCES analyses(analysis_id)); CREATE TABLE IF NOT EXISTS url_analyses(url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,analysis_id INTEGER,url_safe_representation TEXT,risk_score INTEGER,findings TEXT,FOREIGN KEY(analysis_id) REFERENCES analyses(analysis_id));'''); c.commit(); c.close()

def save_analysis(result):
    c=conn(); cur=c.execute("INSERT INTO analyses(sender_domain,subject,risk_score,classification) VALUES(?,?,?,?)",(result['sender']['domain'],result['input']['subject'],result['risk_score'],result['classification'])); aid=cur.lastrowid
    for x in result['contributions']: c.execute("INSERT INTO indicators(analysis_id,indicator_type,description,severity,points) VALUES(?,?,?,?,?)",(aid,x['indicator'],x['description'],x['severity'],x['points']))
    for u in result['urls']: c.execute("INSERT INTO url_analyses(analysis_id,url_safe_representation,risk_score,findings) VALUES(?,?,?,?)",(aid,u['url'],u['score'],json.dumps(u['findings'])))
    c.commit(); c.close(); return aid
