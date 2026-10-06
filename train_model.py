import pandas as pd, joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
ROOT=Path(__file__).resolve().parents[1]; data=pd.read_csv(ROOT/'data/phishing_email_dataset.csv')
X=(data.subject.fillna('')+' '+data.body.fillna('')); y=(data.label=='PHISHING').astype(int)
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42)
model=Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=12000)),('clf',LogisticRegression(max_iter=500,class_weight='balanced'))]); model.fit(Xtr,ytr); pred=model.predict(Xte)
print(classification_report(yte,pred,target_names=['LEGITIMATE','PHISHING'])); print('Confusion matrix:\n',confusion_matrix(yte,pred))
(ROOT/'models').mkdir(exist_ok=True); joblib.dump(model,ROOT/'models/phishing_tfidf_logreg.joblib'); print('Saved model.')
