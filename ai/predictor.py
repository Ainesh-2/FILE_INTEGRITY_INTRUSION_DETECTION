import joblib

model = joblib.load("ai/intrusion_model.pkl")


def predict_intrusion(features):
    label = model.predict([features])[0]
    confidence = max(model.predict_proba([features])[0])
    return label, confidence
