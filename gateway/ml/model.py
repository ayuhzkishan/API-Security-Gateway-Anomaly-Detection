from sklearn.ensemble import IsolationForest
import numpy as np
import os
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'anomaly_model.joblib')

# Characters that frequently appear in attack payloads
SUSPICIOUS_CHARS = set("'\";<>=()[]{}\\|`~!@#$%^&*")


class AnomalyDetector:
    def __init__(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
        else:
            # Fallback model trained on synthetic normal data if not explicitly trained
            self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            # Dummy normal data — 8 features (must match extract_features)
            rng = np.random.default_rng(42)
            X_dummy = np.column_stack([
                rng.integers(0, 800, 100),    # payload_size
                rng.integers(1, 40, 100),      # path_length
                rng.integers(0, 2, 100),       # method_encoded
                rng.integers(4, 12, 100),      # header_count
                rng.integers(1, 5, 100),       # path_depth
                np.zeros(100, dtype=int),      # suspicious_chars (normal = 0)
                rng.integers(10, 120, 100),    # ua_length
                np.zeros(100, dtype=int),      # missing_ua (normal = 0)
            ])
            self.model.fit(X_dummy)
            joblib.dump(self.model, MODEL_PATH)

    def extract_features(self, request_data: dict) -> np.ndarray:
        """
        Extract 8 numerical features from a request dict.

        Features
        --------
        1. payload_size    – body size in bytes
        2. path_length     – character length of the URL path
        3. method_encoded  – 1 for write methods (POST/PUT/PATCH), 0 otherwise
        4. header_count    – number of HTTP headers
        5. path_depth      – number of '/' segments in the path
        6. suspicious_chars – 1 if path or query contains attack-typical chars
        7. ua_length       – length of the User-Agent string (0 if missing)
        8. missing_ua      – 1 if User-Agent header is absent, else 0
        """
        headers = request_data.get('headers', {})
        # Normalise header keys to lowercase for lookup
        headers_lower = {k.lower(): v for k, v in headers.items()}

        payload_size = request_data.get('payload_size', 0)
        path = request_data.get('path', '/')
        path_length = len(path)
        method = request_data.get('method', 'GET')
        method_encoded = 1 if method in ['POST', 'PUT', 'PATCH'] else 0
        header_count = len(headers)
        path_depth = max(1, path.count('/'))
        suspicious_chars = 1 if any(c in path for c in SUSPICIOUS_CHARS) else 0
        ua = headers_lower.get('user-agent', '')
        ua_length = len(ua)
        missing_ua = 0 if ua else 1

        return np.array([[
            payload_size,
            path_length,
            method_encoded,
            header_count,
            path_depth,
            suspicious_chars,
            ua_length,
            missing_ua,
        ]])

    def predict(self, request_data: dict):
        features = self.extract_features(request_data)
        # Returns 1 for inliers, -1 for anomalies
        prediction = self.model.predict(features)[0]
        # Anomaly score (more negative = more anomalous)
        score = self.model.decision_function(features)[0]

        is_anomalous = prediction == -1
        return is_anomalous, float(score)


anomaly_detector = AnomalyDetector()
