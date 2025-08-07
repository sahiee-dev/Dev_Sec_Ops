from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import sys
import os
import pandas as pd
import json
import asyncio
from datetime import datetime
import traceback

# Add project modules to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from data_processing.real_dataset_loader import LoghubDatasetLoader
from ml_engine.advanced_detector import AdvancedAnomalyDetector
from database.db_manager import SessionBasedAnomalyDatabase

# Create FastAPI application
app = FastAPI(
    title="Advanced DevSecOps Anomaly Detection API v2.0",
    description="Production-ready anomaly detection with session-based analysis",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Global instances
dataset_loader = LoghubDatasetLoader()
detector = AdvancedAnomalyDetector()
db_manager = SessionBasedAnomalyDatabase()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"✅ WebSocket client connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"🔌 WebSocket client disconnected. Total connections: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        if not self.active_connections:
            print("⚠️ No WebSocket connections to broadcast to")
            return
        
        print(f"📡 Broadcasting to {len(self.active_connections)} WebSocket connections...")
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
                print(f"✅ Message sent to WebSocket client")
            except Exception as e:
                print(f"❌ Failed to send message to WebSocket client: {e}")
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    await db_manager.initialize_database()
    print("🚀 Advanced DevSecOps API v2.0 with Session-Based Analysis - Ready!")

# API Routes
@app.get("/", tags=["Home"])
def home():
    """Advanced system welcome with session-based capabilities"""
    return {
        "message": "🛡️ Advanced DevSecOps Anomaly Detection System v2.0",
        "features": [
            "🔍 Real Linux system log analysis",
            "🤖 Ensemble ML models (Isolation Forest + One-Class SVM)", 
            "📊 Session-based data analysis",
            "🚀 WebSocket live updates",
            "💾 SQLite database integration",
            "📈 Per-session threat analysis"
        ],
        "status": "operational",
        "model_trained": detector.is_trained,
        "real_data_enabled": True,
        "session_based": True,
        "version": "2.0.0"
    }

@app.post("/train-on-real-data", tags=["Machine Learning"])
async def train_on_real_data():
    """Train ML models on real Linux system logs"""
    try:
        print("🚀 Starting training on Linux dataset...")
        start_time = datetime.now()
        
        # Download Linux dataset if needed
        if not dataset_loader.download_dataset('Linux'):
            raise HTTPException(status_code=400, detail="Failed to download Linux dataset")
        
        # Parse and prepare real log data
        print("📊 Processing real Linux logs...")
        df = dataset_loader.extract_and_parse_logs('Linux')
        
        if df.empty:
            raise HTTPException(status_code=400, detail="No data found in Linux dataset")
        
        # Prepare ML features from real data
        df_processed = dataset_loader.prepare_ml_features(df)
        
        # Sample data for training (use larger sample for better accuracy)
        sample_size = min(5000, len(df_processed))
        df_sample = df_processed.sample(n=sample_size, random_state=42)
        
        # Train advanced models
        training_stats = detector.train(df_sample)
        
        end_time = datetime.now()
        training_duration = (end_time - start_time).total_seconds()
        
        # Broadcast training completion to connected clients
        broadcast_message = {
            "type": "training_complete",
            "data": {
                "samples": sample_size,
                "duration": f"{training_duration:.2f}s",
                "timestamp": datetime.now().isoformat(),
                "message": "AI model training completed successfully"
            }
        }
        
        print("📡 Broadcasting training completion...")
        await manager.broadcast(broadcast_message)
        
        return {
            "message": "✅ Advanced training completed successfully!",
            "training_samples": sample_size,
            "training_time": f"{training_duration:.2f} seconds",
            "model_status": "trained and ready for session-based detection",
            "real_data_enabled": True
        }
        
    except Exception as e:
        print(f"❌ Training failed: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

@app.get("/test-real-detection", tags=["Machine Learning"])
async def test_real_detection():
    """Test anomaly detection on real Linux logs - session-based analysis"""
    if not detector.is_trained:
        raise HTTPException(status_code=400, detail="❌ Advanced models not trained yet")
    
    try:
        print("🚀 Starting new session-based anomaly detection...")
        
        # Start a new session (clears previous data)
        session_id = await db_manager.start_new_session()
        start_time = datetime.now()
        
        # Get fresh Linux log data for testing
        df = dataset_loader.extract_and_parse_logs('Linux')
        df_processed = dataset_loader.prepare_ml_features(df)
        
        # Test on a reasonable sample
        test_size = min(100, len(df_processed))
        test_data = df_processed.sample(n=test_size, random_state=456)
        
        # Get predictions from advanced ensemble
        results = detector.predict(test_data)
        
        # Store results in database for this session only
        storage_success = await db_manager.store_session_results(results['predictions'])
        
        if not storage_success:
            print("⚠️ Database storage failed, but detection completed")
        
        # Calculate metrics
        anomaly_count = results['summary']['anomalies_detected']
        normal_count = results['summary']['normal_behavior']
        threat_rate = (anomaly_count / test_size) * 100 if test_size > 0 else 0
        
        # Broadcast detection results
        broadcast_message = {
            "type": "session_detection_complete",
            "data": {
                "session_id": session_id,
                "total_analyzed": test_size,
                "anomalies_found": anomaly_count,
                "normal_found": normal_count,
                "threat_rate": round(threat_rate, 2),
                "timestamp": datetime.now().isoformat(),
                "message": f"Session analysis complete: {anomaly_count} threats found",
                "storage_success": storage_success
            }
        }
        
        print("📡 Broadcasting session detection completion...")
        await manager.broadcast(broadcast_message)
        
        print(f"✅ Session analysis complete: {anomaly_count} threats detected in session {session_id}")
        
        return {
            "message": f"🔍 Session analysis complete: {anomaly_count} threats detected",
            "session_id": session_id,
            "total_analyzed": test_size,
            "anomalies_detected": anomaly_count,
            "normal_behavior": normal_count,
            "threat_rate": round(threat_rate, 2),
            "session_based": True,
            "database_stored": storage_success
        }
        
    except Exception as e:
        print(f"❌ Session detection failed: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")

@app.get("/real-time-chart-data", tags=["Session Analytics"])
async def get_session_chart_data():
    """Get session-based data for dashboard charts"""
    try:
        print("📊 Fetching session-based chart data...")
        
        # Get current session data
        timeline_data = await db_manager.get_session_timeline_data()
        category_data = await db_manager.get_session_threat_categories()
        pattern_data = await db_manager.get_session_hourly_patterns()
        stats = await db_manager.get_session_statistics()
        
        response_data = {
            "timeline_data": timeline_data,
            "threat_categories": category_data,
            "hourly_patterns": pattern_data,
            "session_stats": stats,
            "last_updated": datetime.now().isoformat(),
            "data_source": "session_based_analysis",
            "session_id": stats.get('session_id')
        }
        
        print("✅ Session-based chart data prepared successfully")
        return response_data
        
    except Exception as e:
        print(f"❌ Failed to get session chart data: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Chart data retrieval failed: {str(e)}")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Send periodic updates every 30 seconds
            await asyncio.sleep(30)
            
            try:
                # Get latest statistics
                stats = await db_manager.get_session_statistics()
                
                await websocket.send_text(json.dumps({
                    "type": "periodic_update",
                    "data": stats,
                    "timestamp": datetime.now().isoformat(),
                    "message": "Periodic session statistics update"
                }))
                
                print("📡 Sent periodic update via WebSocket")
                
            except Exception as e:
                print(f"❌ Error sending periodic update: {e}")
                break
            
    except WebSocketDisconnect:
        print("🔌 WebSocket client disconnected")
        manager.disconnect(websocket)
    except Exception as e:
        print(f"❌ WebSocket error: {e}")
        manager.disconnect(websocket)

@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "features": {
            "session_based_analysis": True,
            "database_storage": True,
            "websocket_support": True,
            "ml_ensemble": detector.is_trained
        },
        "websocket_connections": len(manager.active_connections)
    }

# Run the application
if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting Advanced DevSecOps API v2.0 with Session-Based Analysis...")
    print("📖 Interactive documentation: http://localhost:8000/docs")
    print("🌐 API Home: http://localhost:8000")
    print("📊 Session-based charts: Database integration enabled")
    print("🔌 WebSocket endpoint: ws://localhost:8000/ws")
    
    uvicorn.run("advanced_main:app", host="0.0.0.0", port=8000, reload=True)
