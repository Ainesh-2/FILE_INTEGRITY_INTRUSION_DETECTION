import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

df = pd.read_csv("ai/training_data.csv")
X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier(n_estimators=120, max_depth=10)

model.fit(X_train, y_train)
joblib.dump(model, "ai/ransomware_model.pkl")

print("Model trained and saved to ai/ransomware_model.pkl")
