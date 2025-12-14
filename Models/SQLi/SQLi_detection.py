import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from xgboost import XGBClassifier
import joblib

# Load data
url = 'https://raw.githubusercontent.com/ankitkumarhello20/sql-injection-dataset/main/SqlQueriesData.csv'
data = pd.read_csv(url, encoding='unicode_escape')
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

print("Original distribution:")
print(f"Class 0 (Safe SQL): {(data['Label']==0).sum()}")
print(f"Class 1 (Injection): {(data['Label']==1).sum()}")
print(f"Class 2 (Union): {(data['Label']==2).sum()}")

# Binary classification: 0=Safe, 1=Malicious
data['Label'] = data['Label'].apply(lambda x: 0 if x == 0 else 1)

# CREATE AUGMENTED DATA - BALANCED
# Safe examples - normal user input (300+ examples)
safe_examples = []

# Simple words
safe_examples.extend(['hello', 'world', 'test', 'admin', 'user', 'password', 'username', 
                      'email', 'phone', 'address', 'name', 'title', 'product', 'service',
                      'customer', 'order', 'payment', 'account', 'profile', 'settings'])

# Two-word phrases  
safe_examples.extend(['hello world', 'test user', 'user account', 'email address', 
                      'phone number', 'first name', 'last name', 'product name', 
                      'order number', 'customer service'])

# Numbers and IDs
safe_examples.extend(['1', '12', '123', '1234', '12345', '999', '1000', 
                      'abc123', 'test123', 'user123', 'id123', 'order123'])

# Emails
safe_examples.extend(['user@example.com', 'test@test.com', 'admin@site.com',
                      'john@doe.com', 'info@company.com'])

# Names
safe_examples.extend(['John Smith', 'Jane Doe', 'Bob Johnson', 'Alice Williams',
                      'John', 'Jane', 'Bob', 'Alice', 'Mike', 'Sarah'])

# Places
safe_examples.extend(['New York', 'Los Angeles', 'Chicago', 'London', 'Paris'])

# Products
safe_examples.extend(['laptop', 'phone', 'tablet', 'camera', 'book', 'shoes',
                      'shirt', 'watch', 'bag', 'furniture'])

# Sentences
safe_examples.extend(['this is a test', 'how are you', 'thank you', 'please help',
                      'I need assistance', 'what is this', 'where can I find'])

# Repeat to balance classes (need ~10800/2 = 5400 safe examples)
# Multiply safe examples by 80x to get ~5600
safe_examples = safe_examples * 80

# Malicious examples - comprehensive injection patterns
malicious_examples = [
    # Comment-based
    "admin'--", "admin'#", "user'--", "test'--", "root'--",
    "' --", "' #", "1'--", "1'#",
    
    # Boolean-based
    "' or 1=1--", "' or 1=1#", "' OR 1=1--", "' OR '1'='1",
    "1' OR '1'='1", "' or 'a'='a", "1' or 1=1--",
    
    # Time-based
    "1' AND SLEEP(5)--", "' AND SLEEP(5)--", "1' OR SLEEP(5)--",
    "1' and sleep(5) and '1'='1", "' OR SLEEP(10)--",
    
    # UNION-based  
    "' UNION SELECT NULL--", "1' UNION SELECT NULL--",
    "' UNION SELECT password FROM users--",
    "' UNION SELECT username, password FROM users--",
    "' UNION ALL SELECT NULL, NULL--",
    
    # Command injection
    "'; DROP TABLE users--", "'; DELETE FROM users--",
    "; DROP TABLE users--", "' DROP TABLE", "'; DROP--",
    "'; SELECT * FROM users--",
    
    # Parenthesis bypass
    "1') OR ('1'='1", "1') OR 1=1--", "') OR ('a'='a",
    
    # Mixed case
    "' Or 1=1--", "' oR 1=1--", "Admin'--", "ADMIN'--",
]

# Repeat malicious examples to balance better (need ~5600 to match safe)
# 35 unique patterns * 160 = 5600
malicious_examples = malicious_examples * 160

# Add augmented data
safe_df = pd.DataFrame({'Query': safe_examples, 'Label': [0]*len(safe_examples)})
mal_df = pd.DataFrame({'Query': malicious_examples, 'Label': [1]*len(malicious_examples)})
data = pd.concat([data, safe_df, mal_df], ignore_index=True)

print(f"\n✅ After augmentation:")
print(f"Safe: {(data['Label']==0).sum()}")
print(f"Malicious: {(data['Label']==1).sum()}")
print(f"Total: {len(data)}")

# Prepare data
X = data['Query']
y = data['Label']

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=12, stratify=y
)

# Create pipeline
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        max_features=2000,
        ngram_range=(3, 5),
        analyzer='char',
        min_df=5,
        max_df=0.85
    )),
    ('classifier', XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.2,
        subsample=0.7,
        colsample_bytree=0.7,
        min_child_weight=10,
        gamma=2,
        reg_alpha=1,
        reg_lambda=3,
        random_state=42,
        eval_metric='logloss'
    ))
])

# Train
print("\nTraining...")
pipeline.fit(X_train, y_train)

# Evaluate
y_test_pred = pipeline.predict(X_test)
acc_test = accuracy_score(y_test, y_test_pred)

print(f"\nTest Accuracy: {acc_test:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_test_pred, target_names=['Safe', 'Malicious']))

cm = confusion_matrix(y_test, y_test_pred)
print(f"\nTrue Negatives (Safe ✓): {cm[0][0]}")
print(f"False Positives (Safe → Malicious): {cm[0][1]}")  
print(f"False Negatives (Malicious → Safe): {cm[1][0]}")
print(f"True Positives (Malicious ✓): {cm[1][1]}")

# Save
joblib.dump(pipeline, 'sql_injection_model.pkl')
print("\n✅ Model saved!")

# Inference demo
print("\n" + "="*70)
print("INFERENCE DEMO")
print("="*70)

model = joblib.load('sql_injection_model.pkl')

test_cases = [
    # Safe inputs
    ("hello", "normal text"),
    ("user123", "username"),
    ("test@example.com", "email"),
    ("John Smith", "name"),
    
    # Malicious payloads
    ("' OR 1=1--", "boolean injection"),
    ("admin'--", "comment injection"),
    ("1' AND SLEEP(5)--", "time-based injection"),
    ("'; DROP TABLE users--", "command injection"),
]

for query, note in test_cases:
    pred = model.predict([query])[0]
    proba = model.predict_proba([query])[0]
    
    emoji = "🚨" if pred == 1 else "✅"
    label = "MALICIOUS" if pred == 1 else "SAFE"
    conf = max(proba)
    
    print(f"\n{emoji} {label} ({conf:.1%}) - {note}")
    print(f"   Input: {query}")