from sklearn.ensemble import IsolationForest
import numpy as np
import os
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'anomaly_model.joblib')

class AnomalyDetector:
    def __init__(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
        else:
            # Fallback model trained on dummy data if not explicitly trained
            self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            # Dummy normal data features: [payload_size, path_length, method_encoded, header_count]
            X_dummy = np.array([
                [10, 5, 0, 5],
                [50, 10, 1, 6],
                [0, 8, 0, 4],
                [100, 12, 1, 6],
                [20, 6, 0, 5]
            ] * 20)
            self.model.fit(X_dummy)
            joblib.dump(self.model, MODEL_PATH)

    def extract_features(self, request_data):
        # request_data: dict with payload_size, path, method, headers
        payload_size = request_data.get('payload_size', 0)
        path_length = len(request_data.get('path', '/'))
        method = request_data.get('method', 'GET')
        method_encoded = 1 if method in ['POST', 'PUT', 'PATCH'] else 0
        header_count = len(request_data.get('headers', {}))
        
        return np.array([[payload_size, path_length, method_encoded, header_count]])

    def predict(self, request_data):
        features = self.extract_features(request_data)
        # Returns 1 for inliers, -1 for anomalies
        prediction = self.model.predict(features)[0]
        # Anomaly score (negative is more anomalous)
        score = self.model.decision_function(features)[0]
        
        is_anomalous = True if prediction == -1 else False
        return is_anomalous, float(score)

anomaly_detector = AnomalyDetector()
