import os
import joblib
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def train():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, 'data')
    models_dir = os.path.join(base_dir, 'models')

    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    # Generate synthetic binary classification dataset (5 features)
    X, y = make_classification(
        n_samples=1200,
        n_features=5,
        n_informative=4,
        n_redundant=1,
        random_state=42
    )

    feature_names = ['packet_rate', 'payload_entropy', 'conn_duration', 'failed_logins', 'port_scan_count']
    df = pd.DataFrame(X, columns=feature_names)
    df['target'] = y

    dataset_path = os.path.join(data_dir, 'dataset.csv')
    df.to_csv(dataset_path, index=False)
    print(f"Dataset saved to {dataset_path}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    accuracy = clf.score(X_test, y_test)
    print(f"Random Forest trained successfully with test accuracy: {accuracy:.4f}")

    model_path = os.path.join(models_dir, 'random_forest.joblib')
    joblib.dump({
        'model': clf,
        'feature_names': feature_names
    }, model_path)
    print(f"Model saved to {model_path}")

if __name__ == '__main__':
    train()
