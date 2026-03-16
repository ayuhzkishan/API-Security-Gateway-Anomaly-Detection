import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

def train():
    # Synthetic normal data
    # Features: payload_size, path_length, method_encoded, header_count
    normal_data = []
    for _ in range(1000):
        # Normal GET requests (small payload, short/medium path)
        normal_data.append([np.random.randint(0, 50), np.random.randint(1, 40), 0, np.random.randint(4, 9)])
        # Normal POST requests (medium payload, short/medium path)
        normal_data.append([np.random.randint(50, 800), np.random.randint(5, 50), 1, np.random.randint(5, 12)])
        
    X_train = np.array(normal_data)
    
    # Train model
    # Contamination defines the expected proportion of outliers (2% here)
    model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
    model.fit(X_train)
    
    # Save model
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'anomaly_model.joblib')
    joblib.dump(model, MODEL_PATH)
    print(f"Model trained and saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
