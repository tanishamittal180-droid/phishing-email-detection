from pathlib import Path
import pandas as pd, joblib, json
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix
ROOT=Path(__file__).resolve().parents[1]; df=pd.read_csv(ROOT/'data/phishing_email_dataset.csv'); X=df.subject.fillna('')+' '+df.body.fillna(''); y=(df.label=='PHISHING').astype(int)
_,Xte,_,yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42); m=joblib.load(ROOT/'models/phishing_tfidf_logreg.joblib'); p=m.predict(Xte)
res={'accuracy':accuracy_score(yte,p),'precision':precision_score(yte,p),'recall':recall_score(yte,p),'f1':f1_score(yte,p),'confusion_matrix':confusion_matrix(yte,p).tolist()}; print(json.dumps(res,indent=2)); (ROOT/'models/ml_metrics.json').write_text(json.dumps(res,indent=2))
