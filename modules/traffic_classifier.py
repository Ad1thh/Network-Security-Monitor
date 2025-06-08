import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from typing import Dict, List, Tuple, Union
import json

class HybridTrafficClassifier:
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        self.rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_columns = None
        
        # Define traffic patterns for rule-based classification
        self.traffic_patterns = {
            'http': {'ports': [80, 8080], 'protocol': 'TCP'},
            'https': {'ports': [443, 8443], 'protocol': 'TCP'},
            'dns': {'ports': [53], 'protocol': 'UDP'},
            'ssh': {'ports': [22], 'protocol': 'TCP'},
            'ftp': {'ports': [20, 21], 'protocol': 'TCP'},
            'mail': {'ports': [25, 587, 465, 993, 995], 'protocol': 'TCP'}
        }
        
        # Load configuration if provided
        if config_path:
            self.load_config(config_path)

    def extract_features(self, flow_data: Union[Dict, pd.DataFrame]) -> pd.DataFrame:
        """Extract relevant features for classification."""
        # Convert dict to DataFrame if needed
        if isinstance(flow_data, dict):
            flow_data = pd.DataFrame([flow_data])
        elif not isinstance(flow_data, pd.DataFrame):
            raise ValueError("flow_data must be either a dictionary or DataFrame")
        
        features = flow_data.copy()
        
        # Calculate derived features
        if 'bytes_sent_rate' in features.columns and 'bytes_recv_rate' in features.columns:
            features['bytes_ratio'] = features['bytes_sent_rate'] / (features['bytes_recv_rate'] + 1e-6)
        else:
            features['bytes_ratio'] = 0.0
        
        if 'packets_sent_rate' in features.columns and 'packets_recv_rate' in features.columns:
            features['packets_ratio'] = features['packets_sent_rate'] / (features['packets_recv_rate'] + 1e-6)
        else:
            features['packets_ratio'] = 0.0
        
        # Ensure all required features exist
        required_features = [
            'bytes_sent_rate', 'bytes_recv_rate', 'packets_sent_rate', 'packets_recv_rate',
            'bytes_ratio', 'packets_ratio'
        ]
        
        for feature in required_features:
            if feature not in features:
                features[feature] = 0.0
        
        # Add error and drop features if they exist
        for feature in ['errin', 'errout', 'dropin', 'dropout']:
            if feature not in features:
                features[feature] = 0
        
        return features[required_features + ['errin', 'errout', 'dropin', 'dropout']]
        
    def rule_based_classify(self, flow_data: Union[Dict, pd.DataFrame]) -> List[str]:
        """Apply rule-based classification."""
        # Convert dict to DataFrame if needed
        if isinstance(flow_data, dict):
            flow_data = pd.DataFrame([flow_data])
        
        classifications = []
        
        for _, flow in flow_data.iterrows():
            bytes_sent = flow.get('bytes_sent_rate', 0)
            bytes_recv = flow.get('bytes_recv_rate', 0)
            packets_sent = flow.get('packets_sent_rate', 0)
            packets_recv = flow.get('packets_recv_rate', 0)
            
            # Classify based on traffic patterns
            if bytes_sent > bytes_recv * 2 and bytes_sent > 1000:  # Significant upload
                classifications.append('upload')
            elif bytes_recv > bytes_sent * 2 and bytes_recv > 1000:  # Significant download
                classifications.append('download')
            elif packets_sent < 10 and packets_recv < 10:  # Low traffic, likely interactive
                classifications.append('interactive')
            elif bytes_sent > 0 or bytes_recv > 0:  # Mixed traffic
                classifications.append('mixed')
            else:  # No significant traffic
                classifications.append('idle')
                
        return classifications
        
    def ml_classify(self, features: pd.DataFrame) -> List[str]:
        """Apply machine learning-based classification."""
        if not self.is_trained:
            return ['unknown'] * len(features)
            
        try:
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Make predictions
            predictions = self.rf_classifier.predict(features_scaled)
            return predictions.tolist()
            
        except Exception as e:
            self.logger.error(f"Error in ML classification: {str(e)}")
            return ['error'] * len(features)
    
    def predict(self, flow_data: Union[Dict, pd.DataFrame]) -> List[str]:
        """Classify network traffic using hybrid approach."""
        try:
            # Handle single dictionary input
            if isinstance(flow_data, dict):
                flow_data = pd.DataFrame([flow_data])
            
            # Extract features
            features = self.extract_features(flow_data)
            
            # Get rule-based classification
            rule_based = self.rule_based_classify(flow_data)
            
            # Get ML-based classification if model is trained
            if self.is_trained and len(features) > 0:
                try:
                    features_scaled = self.scaler.transform(features)
                    ml_based = self.rf_classifier.predict(features_scaled).tolist()
                except Exception as e:
                    self.logger.error(f"ML classification failed: {str(e)}")
                    ml_based = ['unknown'] * len(features)
            else:
                ml_based = ['unknown'] * len(features)
            
            # Combine classifications (prefer ML when trained)
            final_classifications = []
            for rb, mb in zip(rule_based, ml_based):
                if mb != 'unknown' and mb != 'error':
                    final_classifications.append(mb)
                else:
                    final_classifications.append(rb)
            
            return final_classifications
            
        except Exception as e:
            self.logger.error(f"Error classifying traffic: {str(e)}")
            if isinstance(flow_data, dict):
                return ['unknown']
            return ['unknown'] * len(flow_data)
            
    def train(self, training_data: pd.DataFrame, labels: List[str]):
        """Train the ML classifier."""
        try:
            features = self.extract_features(training_data)
            
            # Scale features
            self.scaler.fit(features)
            features_scaled = self.scaler.transform(features)
            
            # Train classifier
            self.rf_classifier.fit(features_scaled, labels)
            self.is_trained = True
            
            self.logger.info("ML classifier trained successfully")
            
        except Exception as e:
            self.logger.error(f"Error training classifier: {str(e)}")
            
    def get_traffic_patterns(self) -> Dict:
        """Get current traffic patterns."""
        return self.traffic_patterns

    def preprocess_features(self, df: pd.DataFrame) -> np.ndarray:
        """Preprocess features for model input."""
        # Select numeric columns
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        self.feature_columns = numeric_columns.tolist()
        
        # Handle protocol and flags columns
        if 'protocols' in df.columns:
            protocols = pd.get_dummies(df['protocols'].apply(lambda x: x[0] if x else 'UNKNOWN'))
            df = pd.concat([df[numeric_columns], protocols], axis=1)
            self.feature_columns.extend(protocols.columns.tolist())
        
        if 'tcp_flags' in df.columns:
            df['tcp_flags'] = df['tcp_flags'].apply(lambda x: sum(x) if x else 0)
            self.feature_columns.append('tcp_flags')
        
        X = df[self.feature_columns].values
        return self.scaler.fit_transform(X) if not hasattr(self, 'scaler_mean_') else self.scaler.transform(X)

    def fit(self, X: pd.DataFrame, y: np.ndarray):
        """Train Random Forest model."""
        try:
            # Preprocess features
            X_processed = self.preprocess_features(X)
            self.class_labels = np.unique(y)
            
            # Train Random Forest
            self.logger.info("Training Random Forest classifier...")
            self.rf_classifier.fit(X_processed, y)
            
            self.logger.info("Model training completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error during model training: {str(e)}")
            raise

    def save_model(self, path: str):
        """Save the model."""
        try:
            # Save Random Forest model
            joblib.dump(self.rf_classifier, f"{path}_rf.joblib")
            
            # Save scaler and feature information
            model_info = {
                'feature_columns': self.feature_columns,
                'class_labels': self.class_labels.tolist(),
                'scaler_mean': self.scaler.mean_.tolist(),
                'scaler_scale': self.scaler.scale_.tolist()
            }
            
            with open(f"{path}_info.json", 'w') as f:
                json.dump(model_info, f)
                
            self.logger.info(f"Model saved successfully to {path}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            raise

    def load_model(self, path: str):
        """Load the model."""
        try:
            # Load model info
            with open(f"{path}_info.json", 'r') as f:
                model_info = json.load(f)
            
            self.feature_columns = model_info['feature_columns']
            self.class_labels = np.array(model_info['class_labels'])
            
            # Reconstruct scaler
            self.scaler.mean_ = np.array(model_info['scaler_mean'])
            self.scaler.scale_ = np.array(model_info['scaler_scale'])
            
            # Load Random Forest model
            self.rf_classifier = joblib.load(f"{path}_rf.joblib")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            raise

    def load_config(self, config_path: str):
        """Load configuration from file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Update classifier parameters if specified
            if 'random_forest' in config:
                rf_params = config['random_forest']
                self.rf_classifier.set_params(**rf_params)
                
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            raise

    def update_model(self, training_data_path: str):
        """Update the classifier with new training data."""
        # This would be implemented with actual ML model training
        self.logger.info("Model update requested but not implemented yet") 