import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'anomaly_model.joblib')


def train():
    """
    Train the IsolationForest anomaly detector on synthetic normal traffic.

    Features (8 total)
    ------------------
    1. payload_size      – 0-800 bytes for normal traffic
    2. path_length       – 1-50 chars
    3. method_encoded    – 0 = GET/DELETE, 1 = POST/PUT/PATCH
    4. header_count      – 4-12 headers
    5. path_depth        – 1-5 path segments
    6. suspicious_chars  – 0 for normal (no SQLi/XSS chars in path)
    7. ua_length         – 10-150 chars (real browser UAs are long)
    8. missing_ua        – 0 for normal (bots often omit User-Agent)
    """
    rng = np.random.default_rng(42)
    n = 2000  # samples per category

    # Normal GET requests
    get_data = np.column_stack([
        rng.integers(0, 50, n),       # payload_size (tiny for GET)
        rng.integers(1, 40, n),       # path_length
        np.zeros(n, dtype=int),       # method_encoded = 0
        rng.integers(4, 10, n),       # header_count
        rng.integers(1, 4, n),        # path_depth
        np.zeros(n, dtype=int),       # suspicious_chars = 0
        rng.integers(30, 150, n),     # ua_length
        np.zeros(n, dtype=int),       # missing_ua = 0
    ])

    # Normal POST requests
    post_data = np.column_stack([
        rng.integers(50, 800, n),     # payload_size (larger for POST)
        rng.integers(5, 50, n),       # path_length
        np.ones(n, dtype=int),        # method_encoded = 1
        rng.integers(5, 12, n),       # header_count
        rng.integers(1, 5, n),        # path_depth
        np.zeros(n, dtype=int),       # suspicious_chars = 0
        rng.integers(30, 150, n),     # ua_length
        np.zeros(n, dtype=int),       # missing_ua = 0
    ])

    X_train = np.vstack([get_data, post_data])

    # Contamination = expected % of anomalies in training set (2%)
    model = IsolationForest(n_estimators=150, contamination=0.02, random_state=42)
    model.fit(X_train)

    joblib.dump(model, MODEL_PATH)
    print(f"✅ Model trained on {len(X_train)} samples and saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
