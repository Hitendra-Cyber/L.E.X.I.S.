import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

print("⏳ Step 3: Loading balanced dataset...")
df = pd.read_csv("network_logs_sample.csv")

# 1. Clean Data (Replace infinity values with NaN, then drop NaNs)
# Network logs sometimes divide by zero creating infinite values which crash ML models
print("🧹 Cleaning data and handling infinite/missing values...")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# 2. Separate Features (X) and Target Label (y)
X = df.drop(columns=['Label'])
y = df['Label']

# 3. Split data into Training (80%) and Testing (20%) sets
print("⚖️ Splitting data into train and test sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 4. Initialize and Train the Random Forest Classifier
# We limit max_depth and n_estimators so it runs fast and doesn't create a massive file
print("🤖 Training Random Forest Classifier (this may take a minute)...")
model = RandomForestClassifier(n_estimators=50, max_depth=15, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 5. Evaluate the model
print("📊 Evaluating model on unseen test data...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("\n" + "="*50)
print(f"🎯 MODEL ACCURACY: {accuracy * 100:.2f}%")
print("="*50)
print("\n📝 DETAILED CLASSIFICATION REPORT:")
print(classification_report(y_test, y_pred))
print("="*50)

# 6. Save the trained model and feature names for our Streamlit dashboard
print("💾 Saving model and feature list to disk...")
with open("ids_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("model_features.pkl", "wb") as f:
    pickle.dump(list(X.columns), f)

print("🎉 Success! Saved 'ids_model.pkl' and 'model_features.pkl'.")