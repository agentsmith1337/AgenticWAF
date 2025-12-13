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

# Shuffle
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

# Check original class distribution
print("Original class distribution:")
print(data['Label'].value_counts().sort_index())

# BINARY CLASSIFICATION: Combine class 1 and 2 as "malicious"
# 0 = Safe, 1 = Any type of injection
data['Label'] = data['Label'].apply(lambda x: 0 if x == 0 else 1)

print("\nBinary class distribution:")
print(data['Label'].value_counts().sort_index())

# Use the Query column directly
X = data['Query']
y = data['Label']

# Split with stratification
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=12, stratify=y
)

# Create pipeline with optimized parameters
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 5),      # Capture patterns up to 5 characters
        analyzer='char',          # Character-level for SQL patterns
        min_df=2,
        max_df=0.95
    )),
    ('classifier', XGBClassifier(
        n_estimators=400,
        max_depth=12,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        random_state=42,
        eval_metric='logloss',
        tree_method='hist'
    ))
])

# Train
print("\nTraining binary classification model...")
pipeline.fit(X_train, y_train)

# Evaluate
y_train_pred = pipeline.predict(X_train)
y_test_pred = pipeline.predict(X_test)

acc_train = accuracy_score(y_train, y_train_pred)
acc_test = accuracy_score(y_test, y_test_pred)

print(f"\nTraining Accuracy: {acc_train:.7f}")
print(f"Test Accuracy: {acc_test:.7f}")

# Detailed classification report
print("\nClassification Report:")
print(classification_report(y_test, y_test_pred, target_names=['Safe', 'Malicious']))

# Confusion matrix
print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_test_pred)
print(f"True Negatives (Safe correctly): {cm[0][0]}")
print(f"False Positives (Safe flagged as malicious): {cm[0][1]}")
print(f"False Negatives (Malicious missed): {cm[1][0]}")
print(f"True Positives (Malicious caught): {cm[1][1]}")

# Save the model
joblib.dump(pipeline, 'sql_injection_model.pkl')
print("\nModel saved successfully!")

# Demo inference
print("\n" + "="*70)
print("INFERENCE DEMO")
print("="*70)

loaded_model = joblib.load('sql_injection_model.pkl')

test_queries = [
    ("SELECT * FROM users WHERE id=1", "Should be SAFE"),
    ("SELECT * FROM users WHERE username='admin' OR '1'='1'", "Classic OR injection"),
    ("SELECT * FROM products WHERE category='electronics'", "Should be SAFE"),
    ("SELECT * FROM users WHERE id=1; DROP TABLE users--", "SQL command injection"),
    ("SELECT * FROM accounts WHERE username='admin' AND '1'='1'", "AND injection"),
    ("1%' ) ) union all select null,null--", "UNION injection"),
    ("' UNION SELECT password FROM users--", "UNION injection"),
    ("SELECT name FROM users WHERE age > 18", "Should be SAFE"),
    ("' OR 1=1--", "Classic injection"),
    ("admin'--", "Comment injection"),
]

for query, description in test_queries:
    prediction = loaded_model.predict([query])[0]
    probability = loaded_model.predict_proba([query])[0]
    
    emoji = "🚨" if prediction == 1 else "✅"
    label = "MALICIOUS" if prediction == 1 else "SAFE"
    
    print(f"\n{emoji} {label} (confidence: {max(probability):.1%})")
    print(f"   Query: {query}")
    print(f"   Note: {description}")
    print(f"   Probabilities: [Safe: {probability[0]:.1%}, Malicious: {probability[1]:.1%}]")