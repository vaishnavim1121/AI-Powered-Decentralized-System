import os
import joblib
import numpy as np
import shap

_MODEL_DATA = None
_EXPLAINER = None

def _load_model():
    global _MODEL_DATA, _EXPLAINER
    if _MODEL_DATA is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, 'models', 'random_forest.joblib')
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}. Please run src/train_model.py first.")
        _MODEL_DATA = joblib.load(model_path)
        model = _MODEL_DATA['model']
        _EXPLAINER = shap.TreeExplainer(model)
    return _MODEL_DATA['model'], _MODEL_DATA.get('feature_names', None), _EXPLAINER

def predict(features):
    """
    Exposes predict(features) returning dict:
    {'prediction': 'malicious'|'benign', 'confidence': float, 'explanation': dict}
    """
    model, feature_names, explainer = _load_model()
    
    X = np.array(features, dtype=float).reshape(1, -1)
    probs = model.predict_proba(X)[0]
    pred_class_idx = int(np.argmax(probs))
    confidence = float(probs[pred_class_idx])
    
    prediction_label = 'malicious' if pred_class_idx == 1 else 'benign'
    
    shap_vals = explainer.shap_values(X)
    
    if isinstance(shap_vals, list):
        feature_shaps = shap_vals[pred_class_idx][0]
    elif len(np.shape(shap_vals)) == 3:
        feature_shaps = shap_vals[0, :, pred_class_idx]
    else:
        feature_shaps = shap_vals[0]
        
    explanation = {}
    for i, val in enumerate(feature_shaps):
        name = feature_names[i] if (feature_names and i < len(feature_names)) else f"feature_{i+1}"
        explanation[name] = round(float(val), 4)
        
    return {
        'prediction': prediction_label,
        'confidence': round(confidence, 4),
        'explanation': explanation
    }

if __name__ == '__main__':
    sample = [8, 5, 3, 2, 1]
    res = predict(sample)
    print("Sample prediction result:", res)
