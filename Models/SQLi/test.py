import joblib

model = joblib.load('sql_injection_model.pkl')

# Check user input from forms, URL params, etc.
user_input = "login?username=admin&password=' OR 1=1--"

prediction = model.predict([user_input])[0]

if prediction == 1:
    print("Blocked: Potential SQL injection")
else:
    print("Safe")