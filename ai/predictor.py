import joblib

model = joblib.load("ai/ransomware_model.pkl")


def predict_intrusion(features):
    label = model.predict([features])[0]
    confidence = max(model.predict_proba([features])[0])
    return label, confidence
