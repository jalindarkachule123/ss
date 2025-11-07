import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from lime import lime_tabular
import joblib
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class XAIAgent:
    def __init__(self, model_path=None):
        """Initialize the XAI Agent with an optional pre-trained model."""
        self.model = None
        self.explainer = None
        if model_path:
            self.load_model(model_path)

    def load_model(self, model_path):
        """Load a pre-trained model from disk."""
        try:
            self.model = joblib.load(model_path)
            logger.info("Model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise

    def analyze_alert(self, alert_data):
        """Analyze an alert using the loaded model."""
        if self.model is None:
            raise ValueError("Model not loaded")
        
        try:
            # Preprocess alert data
            features = self._preprocess_alert(alert_data)
            
            # Make prediction
            prediction = self.model.predict_proba([features])[0]
            
            return {
                "risk_score": float(prediction[1]),
                "confidence": float(max(prediction)),
                "features": features.tolist()
            }
        except Exception as e:
            logger.error(f"Error analyzing alert: {e}")
            raise

    def generate_explanation(self, analysis_result):
        """Generate an explanation for the model's decision."""
        if self.explainer is None:
            raise ValueError("Explainer not initialized")
        
        try:
            explanation = self.explainer.explain_instance(
                analysis_result["features"], 
                self.model.predict_proba,
                num_features=10
            )
            
            return {
                "feature_importance": explanation.as_list(),
                "explanation_text": self._generate_text_explanation(explanation)
            }
        except Exception as e:
            logger.error(f"Error generating explanation: {e}")
            raise

    def _preprocess_alert(self, alert_data):
        """Preprocess alert data into model-compatible features."""
        # Convert alert data to feature vector
        # This is a placeholder - implement actual preprocessing logic
        return np.array([0] * 10)  # Replace with actual feature extraction

    def _generate_text_explanation(self, explanation):
        """Generate human-readable explanation from LIME output."""
        feature_importance = explanation.as_list()
        text = "Alert Analysis Explanation:\n"
        for feature, importance in feature_importance:
            text += f"- {feature}: {importance:.3f}\n"
        return text

# If running as main script
if __name__ == "__main__":
    # Example usage
    agent = XAIAgent()
    # Add implementation for command-line interface if needed