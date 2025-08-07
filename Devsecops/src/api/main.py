from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import sys
import os
import json
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Add our project modules to the path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import our custom modules
from ml_engine.simple_detector import BeginnerAnomalyDetector
from data_generation.log_simulator import SimpleLogGenerator


app = FastAPI(
    title="DevSecOps Anomaly Detection API",
    description="A beginner-friendly API for detecting suspicious activities in computer logs",
    version="1.0.0"
)

# Add CORS middleware - ADD THIS SECTION
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173","http://localhost:5174", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
# Global instances (shared across all API requests)
detector = BeginnerAnomalyDetector()
generator = SimpleLogGenerator()

# Define what a log entry looks like for our API
class LogEntry(BaseModel):
    timestamp: str
    user: str
    action: str
    ip_address: str
    status: str

class TrainingResponse(BaseModel):
    message: str
    training_samples: int
    training_time: str
    model_status: str

class PredictionResponse(BaseModel):
    total_logs_analyzed: int
    suspicious_count: int
    normal_count: int
    predictions: List[dict]
    analysis_summary: str

# API Routes (endpoints that other programs can call)

@app.get("/", tags=["Home"])
def home():
    """
    Welcome message and API status.
    Visit /docs for interactive API documentation!
    """
    return {
        "message": "🛡️ Welcome to the DevSecOps Anomaly Detection System!",
        "version": "1.0.0",
        "status": "online",
        "model_trained": detector.is_trained,
        "documentation": "/docs",
        "features": [
            "🤖 AI-powered anomaly detection",
            "📊 Real-time log analysis", 
            "🔍 Detailed threat explanations",
            "📈 Training and prediction endpoints"
        ]
    }

@app.get("/status", tags=["System"])
def get_system_status():
    """Get the current system and model status"""
    return {
        "system_status": "healthy",
        "model_trained": detector.is_trained,
        "api_version": "1.0.0",
        "available_endpoints": ["/train", "/predict", "/test", "/generate-data"],
        "last_check": datetime.now().isoformat()
    }

@app.post("/train", response_model=TrainingResponse, tags=["Machine Learning"])
def train_model(sample_count: int = 200):
    """
    Train the AI model with normal log data.
    
    Parameters:
    - sample_count: Number of normal logs to generate for training (default: 200)
    """
    try:
        print(f"🚀 Starting model training with {sample_count} samples...")
        
        start_time = datetime.now()
        
        # Generate normal training data
        print("📊 Generating training data...")
        normal_logs = []
        for i in range(sample_count):
            normal_logs.append(generator.generate_normal_log())
        
        # Train the model
        print("🤖 Training the AI model...")
        detector.train(normal_logs)
        
        end_time = datetime.now()
        training_duration = (end_time - start_time).total_seconds()
        
        response = TrainingResponse(
            message="✅ Model training completed successfully!",
            training_samples=sample_count,
            training_time=f"{training_duration:.2f} seconds",
            model_status="trained and ready"
        )
        
        print("✅ Training completed successfully!")
        return response
        
    except Exception as e:
        print(f"❌ Training failed: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Training failed: {str(e)}"
        )

@app.post("/predict", response_model=PredictionResponse, tags=["Machine Learning"])
def predict_anomalies(logs: List[LogEntry]):
    """
    Analyze logs for suspicious activities.
    
    Send a list of log entries and get back anomaly detection results.
    """
    if not detector.is_trained:
        raise HTTPException(
            status_code=400,
            detail="❌ Model not trained yet. Please call /train endpoint first."
        )
    
    try:
        print(f"🔍 Analyzing {len(logs)} logs for anomalies...")
        
        # Convert Pydantic models to dictionaries
        log_dicts = [log.dict() for log in logs]
        
        # Get predictions from our AI
        results = detector.predict(log_dicts)
        
        # Calculate summary statistics
        suspicious_count = sum(1 for r in results if r['is_suspicious'])
        normal_count = len(results) - suspicious_count
        
        # Create analysis summary
        if suspicious_count == 0:
            summary = "🛡️ All activities appear normal and safe."
        elif suspicious_count == 1:
            summary = f"⚠️ Found 1 suspicious activity that needs attention."
        else:
            summary = f"🚨 Found {suspicious_count} suspicious activities that need immediate attention!"
        
        response = PredictionResponse(
            total_logs_analyzed=len(logs),
            suspicious_count=suspicious_count,
            normal_count=normal_count,
            predictions=results,
            analysis_summary=summary
        )
        
        print(f"✅ Analysis complete: {suspicious_count} suspicious, {normal_count} normal")
        return response
        
    except Exception as e:
        print(f"❌ Prediction failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )

@app.get("/test", tags=["Testing"])
def test_detection():
    """
    Generate test data and run anomaly detection.
    Perfect for testing the system end-to-end!
    """
    if not detector.is_trained:
        raise HTTPException(
            status_code=400,
            detail="❌ Model not trained yet. Please call /train endpoint first."
        )
    
    try:
        print("🧪 Running end-to-end test...")
        
        # Generate mixed test data
        test_logs = []
        
        # Add normal logs
        for i in range(8):
            test_logs.append(generator.generate_normal_log())
        
        # Add suspicious logs  
        for i in range(3):
            test_logs.append(generator.generate_suspicious_log())
        
        # Get predictions
        results = detector.predict(test_logs)
        
        # Calculate statistics (ensure Python types)
        suspicious_count = sum(1 for r in results if r['is_suspicious'])
        normal_count = len(results) - suspicious_count
        
        # Return clean Python data types (not numpy types)
        return {
            "test_type": "Mixed normal and suspicious logs",
            "total_logs": int(len(test_logs)),           # Ensure Python int
            "suspicious_found": int(suspicious_count),   # Ensure Python int
            "normal_found": int(normal_count),           # Ensure Python int
            "expected_suspicious": 3,
            "test_passed": bool(suspicious_count > 0),   # Ensure Python bool
            "detailed_results": results,                 # Now contains only Python types
            "summary": f"Test completed: Found {suspicious_count} suspicious activities out of {len(test_logs)} total logs"
        }
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Test failed: {str(e)}"
        )


@app.get("/generate-data", tags=["Testing"])
def generate_sample_data(normal_count: int = 5, suspicious_count: int = 2):
    """
    Generate sample log data for testing.
    
    Parameters:
    - normal_count: Number of normal logs to generate
    - suspicious_count: Number of suspicious logs to generate
    """
    try:
        sample_logs = []
        
        # Generate normal logs
        for i in range(normal_count):
            log = generator.generate_normal_log()
            log['type'] = 'normal'
            sample_logs.append(log)
        
        # Generate suspicious logs
        for i in range(suspicious_count):
            log = generator.generate_suspicious_log()  
            log['type'] = 'suspicious'
            sample_logs.append(log)
        
        return {
            "message": f"Generated {len(sample_logs)} sample logs",
            "normal_count": normal_count,
            "suspicious_count": suspicious_count,
            "sample_data": sample_logs,
            "usage_tip": "You can copy this data and send it to the /predict endpoint for testing"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Data generation failed: {str(e)}"
        )

# This runs when you execute the file directly
if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting DevSecOps Anomaly Detection API...")
    print("📖 Interactive documentation: http://localhost:8000/docs")
    print("🌐 API Home: http://localhost:8000")
    print("🛑 Press Ctrl+C to stop the server")
    
    # Start the web server (note: "main:app" instead of app)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
