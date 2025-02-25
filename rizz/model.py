import re
import numpy as np
import tldextract
import whois
import requests
import joblib
import onnx
import onnxruntime as ort
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import RandomForestClassifier

# Suspicious words that commonly appear in phishing URLs
SUSPICIOUS_WORDS = ["login", "bank", "secure", "account", "update", "password", "verification", "paypal", "ebay", "confirm"]

# Load PhishTank blacklist
def load_phishtank():
    try:
        phish_df = pd.read_csv("https://data.phishtank.com/data/online-valid.csv")
        return set(phish_df['url'].tolist())
    except:
        return set()

PHISHTANK_BLACKLIST = load_phishtank()

# Feature extraction function
def extract_features(url):
    """ Extracts multiple features from a URL for phishing detection. """
    features = []
    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)
    
    domain = extracted.domain
    suffix = extracted.suffix
    path = parsed_url.path

    # Lexical Features
    features.append(len(url))  # URL Length
    features.append(url.count('.'))  # Count of '.'
    features.append(url.count('/'))  # Count of '/'
    features.append(url.count('-'))  # Count of '-'
    features.append(url.count('@'))  # Count of '@'
    features.append(url.count('?'))  # Count of '?'
    features.append(url.count('&'))  # Count of '&'
    features.append(1 if "https" in url.lower() else 0)  # HTTPS presence
    features.append(sum(1 for word in SUSPICIOUS_WORDS if word in url.lower()))  # Suspicious word count

    # Domain-based Features
    features.append(len(domain))  # Domain Length
    features.append(sum(c.isdigit() for c in domain))  # Numeric characters in domain
    features.append(1 if re.search(r"[0-9]{3,}", domain) else 0)  # Long digit sequences

    # WHOIS-based Features
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = (datetime.now() - creation_date).days if creation_date else -1
        expiry_days = (expiration_date - datetime.now()).days if expiration_date else -1
    except:
        age_days = -1
        expiry_days = -1

    features.append(age_days)  # Domain Age
    features.append(expiry_days)  # Domain Expiry

    # IP Address Feature
    features.append(1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0)  # If domain is an IP address

    # Path-based Features
    features.append(len(path))  # Path Length
    features.append(sum(1 for c in path if c.isdigit()))  # Numbers in Path
    features.append(path.count('/'))  # Path Depth
    features.append(path.count('-'))  # Hyphens in Path

    # Blacklist Features
    features.append(1 if url in PHISHTANK_BLACKLIST else 0)  # PhishTank Match

    return np.array(features)

df1 = pd.read_csv("D:\Wayne\Arish proj\malicious_phish.csv")
urls2 = df1['url'].to_list()
type(df1['type'])
labels2 = [1] * len(urls2)
for i in range(len(df1['type'])):
    if(df1['type'].iloc[i]=='phishing'):
        labels2[i]=1
    elif(df1['type'].iloc[i]=='defacement'):
        labels2[i]=1
    elif(df1['type'].iloc[i]=='malware'):
        labels2[i]=1
    else:
        labels2[i]=0

# Load PhishTank dataset
df1 = pd.read_csv("D:\Wayne\Arish proj\verified_online.csv")
urls = df1['url'].tolist()

labels = [1] * len(urls)  # Phishing labels 

# Generate random safe URLs (for balanced training)
safe_urls = [
    "https://www.google.com",
    "https://www.facebook.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://www.microsoft.com",
]
safe_labels = [0] * len(safe_urls)

# Combine datasets
urls.extend(urls2)
labels.extend(labels2)

# Extract features
X = np.array([extract_features(url) for url in urls])
y = np.array(labels)

# Train Random Forest Model
rf_model = RandomForestClassifier(n_estimators=200, random_state=42)
rf_model.fit(X, y)

# Save as pickle (for testing)
joblib.dump(rf_model, "random_forest.pkl")
print("✅ Random Forest Model Trained!")
