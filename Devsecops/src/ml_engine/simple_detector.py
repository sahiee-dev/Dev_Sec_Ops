from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import numpy as np
from datetime import datetime
import json
import pickle
import os

class BeginnerAnomalyDetector:
    """
    This is our AI detective! 🕵️
    It learns what normal computer behavior looks like,
    then spots anything that seems weird or suspicious.
    """
    
    def __init__(self):
        # This is our AI model - think of it as a smart pattern detector
        self.model = IsolationForest(
            contamination=0.1,  # Expect 10% of data to be anomalies
            random_state=42,    # Makes results consistent for testing
            n_estimators=100    # How many "trees" in our forest
        )
        
        # Keep track of whether our AI has been trained
        self.is_trained = False
        
        # These help convert text to numbers (computers only understand numbers)
        self.encoders = {}
        
        # Store feature names for consistency
        self.feature_names = [
            'hour_of_day', 'day_of_week', 'user_encoded', 
            'action_encoded', 'ip_encoded', 'status_encoded'
        ]
    
    def extract_time_features(self, timestamp_str):
        """
        Extract useful information from timestamps.
        Suspicious activity often happens at weird times!
        """
        try:
            # Convert text timestamp to datetime object
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            
            return {
                'hour_of_day': dt.hour,       # 0-23 (3 AM is suspicious for user activity)
                'day_of_week': dt.weekday(),  # 0-6 (weekend activity might be suspicious)
            }
        except Exception as e:
            print(f"Error parsing timestamp {timestamp_str}: {e}")
            return {'hour_of_day': 12, 'day_of_week': 0}  # Default values
    
    def encode_categorical_features(self, logs, is_training=True):
        """
        Convert text values to numbers.
        Example: 'john_doe' becomes 1, 'jane_smith' becomes 2, etc.
        """
        df = pd.DataFrame(logs)
        
        # Text columns that need to be converted to numbers
        categorical_columns = ['user', 'action', 'ip_address', 'status']
        
        for column in categorical_columns:
            if column not in df.columns:
                print(f"Warning: Column {column} not found in logs")
                continue
                
            encoder_name = f'{column}_encoded'
            
            if is_training:
                # During training, create new encoders
                if column not in self.encoders:
                    self.encoders[column] = LabelEncoder()
                
                # Learn the encoding from training data
                df[encoder_name] = self.encoders[column].fit_transform(df[column].astype(str))
            else:
                # During prediction, use existing encoders
                if column in self.encoders:
                    # Handle new values not seen during training
                    def safe_transform(value):
                        try:
                            return self.encoders[column].transform([str(value)])[0]
                        except ValueError:
                            # If we see a new value, return -1 (this itself might be suspicious!)
                            return -1
                    
                    df[encoder_name] = df[column].astype(str).apply(safe_transform)
                else:
                    print(f"Warning: No encoder found for {column}")
                    df[encoder_name] = 0
        
        return df
    
    def prepare_features(self, logs, is_training=True):
        """
        Convert raw logs into numbers that our AI can understand.
        This is like translating from human language to computer language.
        """
        print(f"📊 Preparing features from {len(logs)} logs...")
        
        features_list = []
        
        for log in logs:
            # Extract time-based features
            time_features = self.extract_time_features(log['timestamp'])
            
            # Create a feature row
            feature_row = {
                'hour_of_day': time_features['hour_of_day'],
                'day_of_week': time_features['day_of_week'],
                'user': log.get('user', 'unknown'),
                'action': log.get('action', 'unknown'),
                'ip_address': log.get('ip_address', '0.0.0.0'),
                'status': log.get('status', 'unknown')
            }
            
            features_list.append(feature_row)
        
        # Convert categorical features to numbers
        df = self.encode_categorical_features(features_list, is_training)
        
        # Select only the numeric features for our model
        feature_columns = self.feature_names
        
        # Make sure all columns exist
        for col in feature_columns:
            if col not in df.columns:
                print(f"Warning: Missing feature {col}, setting to 0")
                df[col] = 0
        
        features_array = df[feature_columns].values
        
        print(f"✅ Created {features_array.shape[0]} feature rows with {features_array.shape[1]} features each")
        return features_array
    
    def train(self, normal_logs):
        """
        Teach our AI what normal computer behavior looks like.
        This is like showing a security guard what a normal day looks like.
        """
        print("🤖 Training the AI Detective...")
        print(f"📚 Learning from {len(normal_logs)} examples of normal behavior")
        
        # Convert logs to numbers
        features = self.prepare_features(normal_logs, is_training=True)
        
        # Train the AI model (this is where the magic happens!)
        print("🧠 AI is learning patterns...")
        self.model.fit(features)
        
        # Mark as trained
        self.is_trained = True
        
        print("✅ AI training completed!")
        print(f"🎯 The AI has learned what normal looks like from {len(normal_logs)} examples")
        
        # Calculate some statistics
        scores = self.model.decision_function(features)
        threshold = np.percentile(scores, 10)  # 10th percentile as threshold
        print(f"📈 Anomaly detection threshold set to: {threshold:.3f}")
    
    def predict(self, new_logs):
        """
        Ask our trained AI: "Are these logs normal or suspicious?"
        """
        if not self.is_trained:
            print("❌ Error: AI hasn't been trained yet!")
            print("   Call the train() method first with normal logs.")
            return []

        print(f"🔍 Analyzing {len(new_logs)} new logs for suspicious activity...")
        
        # Convert logs to numbers
        features = self.prepare_features(new_logs, is_training=False)
        
        # Get predictions (-1 = suspicious, 1 = normal)
        predictions = self.model.predict(features)
        
        # Get confidence scores (more negative = more suspicious)
        confidence_scores = self.model.decision_function(features)
        
        # Process results
        results = []
        suspicious_count = 0
        
        for i, (prediction, score) in enumerate(zip(predictions, confidence_scores)):
            # FIXED: Convert numpy types to Python types
            is_suspicious = bool(prediction == -1)  # Convert numpy.bool_ to Python bool
            confidence_score = float(score)         # Convert numpy.float64 to Python float
            
            if is_suspicious:
                suspicious_count += 1
            
            # Create human-readable confidence level
            if confidence_score < -0.2:
                confidence_level = "Very High"
            elif confidence_score < -0.1:
                confidence_level = "High" 
            elif confidence_score < 0:
                confidence_level = "Medium"
            else:
                confidence_level = "Low"
            
            result = {
                'log_index': int(i),                    # Ensure it's Python int
                'original_log': new_logs[i],
                'is_suspicious': is_suspicious,         # Now Python bool
                'confidence_score': confidence_score,   # Now Python float
                'confidence_level': confidence_level,
                'analysis': self._generate_analysis(new_logs[i], is_suspicious, confidence_score)
            }
            
            results.append(result)
        
        print(f"🚨 Found {suspicious_count} suspicious activities out of {len(new_logs)} logs")
        return results

    
    def _generate_analysis(self, log, is_suspicious, score):
        """
        Generate human-readable explanation of why something is suspicious.
        """
        if not is_suspicious:
            return "This activity appears normal and expected."
        
        # Extract time info
        time_features = self.extract_time_features(log['timestamp'])
        hour = time_features['hour_of_day']
        
        reasons = []
        
        # Check for suspicious timing
        if hour < 6 or hour > 22:
            reasons.append(f"Unusual time of activity ({hour:02d}:00)")
        
        # Check for unknown users
        if log.get('user') == 'unknown_user':
            reasons.append("Unknown user account")
        
        # Check for failed status
        if log.get('status') == 'failed':
            reasons.append("Failed operation")
        
        # Check for admin activity
        if 'admin' in log.get('user', '').lower():
            reasons.append("Administrative account activity")
        
        if reasons:
            return f"Suspicious because: {', '.join(reasons)}"
        else:
            return f"Anomalous pattern detected (confidence: {score:.3f})"
    
    def save_model(self, filepath):
        """Save the trained model to disk"""
        if not self.is_trained:
            print("❌ Cannot save untrained model")
            return False
        
        model_data = {
            'model': self.model,
            'encoders': self.encoders,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            print(f"✅ Model saved to {filepath}")
            return True
        except Exception as e:
            print(f"❌ Error saving model: {e}")
            return False
    
    def load_model(self, filepath):
        """Load a trained model from disk"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.encoders = model_data['encoders']
            self.feature_names = model_data['feature_names']
            self.is_trained = model_data['is_trained']
            
            print(f"✅ Model loaded from {filepath}")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False

# Test our detector
if __name__ == "__main__":
    print("🤖 Testing our AI Anomaly Detector!")
    print("=" * 60)
    
    # Import our log generator
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    
    from data_generation.log_simulator import SimpleLogGenerator
    
    # Create instances
    generator = SimpleLogGenerator()
    detector = BeginnerAnomalyDetector()
    
    # Step 1: Generate training data (normal logs only)
    print("📊 STEP 1: Generating training data...")
    normal_logs = []
    for i in range(200):  # Generate 200 normal logs
        normal_logs.append(generator.generate_normal_log())
    
    print(f"Generated {len(normal_logs)} normal logs for training")
    
    # Step 2: Train the AI
    print("\n🧠 STEP 2: Training the AI...")
    detector.train(normal_logs)
    
    # Step 3: Test with mixed data
    print("\n🔍 STEP 3: Testing with new logs...")
    test_logs = []
    
    # Add some normal logs
    for i in range(8):
        test_logs.append(generator.generate_normal_log())
    
    # Add some suspicious logs
    for i in range(3):
        test_logs.append(generator.generate_suspicious_log())
    
    print(f"Testing with {len(test_logs)} logs (8 normal + 3 suspicious)")
    
    # Get predictions
    results = detector.predict(test_logs)
    
    # Display results
    print("\n📋 RESULTS:")
    print("-" * 80)
    
    for result in results:
        status = "🚨 SUSPICIOUS" if result['is_suspicious'] else "✅ NORMAL"
        log = result['original_log']
        
        print(f"\n{status} | Confidence: {result['confidence_level']}")
        print(f"   User: {log.get('user', 'N/A')} | Action: {log.get('action', 'N/A')}")
        print(f"   Time: {log.get('timestamp', 'N/A')[:19]}")  # Show just date/time
        print(f"   Analysis: {result['analysis']}")
    
    print(f"\n🎯 Detection completed successfully!")
    
    # Test saving the model
    print(f"\n💾 Testing model save/load...")
    model_path = "../../data/models/test_model.pkl"
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    if detector.save_model(model_path):
        # Test loading
        new_detector = BeginnerAnomalyDetector()
        if new_detector.load_model(model_path):
            print("✅ Model save/load test successful!")
        else:
            print("❌ Model loading failed!")
    else:
        print("❌ Model saving failed!")
