# ADCTIN Project - AI Module (Member 2 - Punitha M)

AI module for security telemetry classification, threat detection, and SHAP model explainability.

## Directory Structure
```
adctin-project/ai-module/
├── data/
│   └── dataset.csv
├── models/
│   └── random_forest.joblib
├── src/
│   ├── __init__.py
│   ├── train_model.py
│   └── predict.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Setup & Installation

1. Create and activate a Python virtual environment:
   ```bash
   cd ai-module
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Train the model:
   ```bash
   python src/train_model.py
   ```
   This will save the trained model artifact to `models/random_forest.joblib`.

4. Test Prediction & Explainability:
   ```bash
   python -c "from src import predict; print(predict([8,5,3,2,1]))"
   ```

   **Sample Output:**
   ```python
   {'prediction': 'malicious', 'confidence': 0.95, 'explanation': {'packet_rate': 0.12, ...}}
   ```
