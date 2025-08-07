import aiosqlite
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import os
import asyncio

class SessionBasedAnomalyDatabase:
    """
    Session-based database manager that resets data for each detection session
    """
    
    def __init__(self, db_path: str = "../../data/session_anomaly_detection.db"):
        self.db_path = db_path
        self.current_session_id = None
        self.ensure_db_directory()
    
    def ensure_db_directory(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        os.makedirs(db_dir, exist_ok=True)
    
    async def initialize_database(self):
        """Create database tables if they don't exist"""
        async with aiosqlite.connect(self.db_path) as db:
            # Session-based detection results table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS session_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    is_anomaly BOOLEAN NOT NULL,
                    confidence_score REAL,
                    threat_category TEXT,
                    source_log TEXT,
                    raw_log_data TEXT,
                    model_version TEXT DEFAULT '2.0',
                    processing_time_ms INTEGER
                )
            ''')
            
            # Session metadata table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    total_logs INTEGER DEFAULT 0,
                    anomalies_detected INTEGER DEFAULT 0,
                    model_version TEXT DEFAULT '2.0'
                )
            ''')
            
            await db.execute('''
                CREATE INDEX IF NOT EXISTS idx_session_detections 
                ON session_detections(session_id, timestamp)
            ''')
            
            await db.commit()
            print("✅ Session-based database initialized")
    
    async def start_new_session(self) -> str:
        """Start a new detection session and clear previous data"""
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.current_session_id = session_id
        
        async with aiosqlite.connect(self.db_path) as db:
            # Clear previous session data
            await db.execute('DELETE FROM session_detections')
            await db.execute('DELETE FROM sessions')
            
            # Insert new session record
            await db.execute('''
                INSERT INTO sessions (session_id, start_time)
                VALUES (?, ?)
            ''', (session_id, datetime.now().isoformat()))
            
            await db.commit()
        
        print(f"🚀 Started new detection session: {session_id}")
        return session_id
    
    def _serialize_log_data(self, log_data):
        """Safely serialize log data to JSON, handling datetime objects"""
        if not log_data:
            return "{}"
        
        serializable_data = {}
        for key, value in log_data.items():
            if hasattr(value, 'isoformat'):  # datetime-like object
                serializable_data[key] = value.isoformat()
            elif hasattr(value, 'item'):  # numpy types
                serializable_data[key] = value.item()
            elif isinstance(value, (int, float, str, bool, type(None))):
                serializable_data[key] = value
            else:
                serializable_data[key] = str(value)
        
        return json.dumps(serializable_data)
    
    async def store_session_results(self, results: List[Dict]) -> bool:
        """Store detection results for the current session only"""
        if not self.current_session_id:
            await self.start_new_session()
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                detection_data = []
                current_time = datetime.now()
                
                print(f"📊 Storing {len(results)} detection results for current session...")
                
                for i, result in enumerate(results):
                    # Create realistic timestamps for this session (spread over last few minutes)
                    timestamp = current_time - timedelta(minutes=len(results)-i-1, seconds=30-i*2)
                    
                    log_data = result.get('log_data', {})
                    serialized_log_data = self._serialize_log_data(log_data)
                    threat_category = self._categorize_threat(log_data, result.get('is_anomaly', False))
                    
                    detection_data.append((
                        self.current_session_id,
                        timestamp.isoformat(),
                        result.get('is_anomaly', False),
                        float(result.get('confidence_score', 0.0)),
                        threat_category,
                        str(log_data.get('source', 'unknown')),
                        serialized_log_data,
                        '2.0',
                        int(result.get('processing_time_ms', 50))
                    ))
                
                await db.executemany('''
                    INSERT INTO session_detections 
                    (session_id, timestamp, is_anomaly, confidence_score, threat_category, 
                     source_log, raw_log_data, model_version, processing_time_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', detection_data)
                
                # Update session summary
                anomaly_count = sum(1 for result in results if result.get('is_anomaly', False))
                await db.execute('''
                    UPDATE sessions 
                    SET total_logs = ?, anomalies_detected = ?, end_time = ?
                    WHERE session_id = ?
                ''', (len(results), anomaly_count, datetime.now().isoformat(), self.current_session_id))
                
                await db.commit()
                print(f"✅ Stored {len(results)} results for session {self.current_session_id}")
                return True
                
        except Exception as e:
            print(f"❌ Failed to store session results: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _categorize_threat(self, log_data: Dict, is_anomaly: bool) -> str:
        """Categorize threats based on log content"""
        if not is_anomaly:
            return "normal"
        
        message = ""
        for key in ['message', 'raw_log', 'request']:
            if key in log_data:
                message = str(log_data[key]).lower()
                break
        
        if 'failed' in message and ('password' in message or 'auth' in message):
            return "failed_authentication"
        elif any(hour in str(log_data.get('timestamp', '')) for hour in ['01:', '02:', '03:', '04:', '05:']):
            return "off_hours_activity"
        elif 'admin' in message or 'root' in message:
            return "privilege_escalation"
        elif any(ext_ip in str(log_data.get('ip_address', '')) for ext_ip in ['203.', '198.', '185.']):
            return "external_ip_access"
        else:
            return "unusual_access_pattern"
    
    async def get_session_timeline_data(self) -> Dict:
        """Get timeline data for current session only"""
        if not self.current_session_id:
            return self._empty_timeline_data()
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute('''
                SELECT COUNT(*) FROM session_detections WHERE session_id = ?
            ''', (self.current_session_id,))
            total_records = (await cursor.fetchone())[0]
            
            if total_records == 0:
                return self._empty_timeline_data()
            
            # Create time buckets for the session data
            cursor = await db.execute('''
                SELECT 
                    strftime('%H:%M', timestamp) as time_bucket,
                    COUNT(*) as total_count,
                    SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomaly_count,
                    SUM(CASE WHEN is_anomaly = 0 THEN 1 ELSE 0 END) as normal_count
                FROM session_detections 
                WHERE session_id = ?
                GROUP BY strftime('%H:%M', timestamp)
                ORDER BY timestamp
            ''', (self.current_session_id,))
            
            rows = await cursor.fetchall()
            
            timeline_data = {
                'timestamps': [],
                'normal_counts': [],
                'anomaly_counts': [],
                'confidence_scores': []
            }
            
            for row in rows:
                timeline_data['timestamps'].append(row[0])  # time_bucket
                timeline_data['normal_counts'].append(row[3])  # normal_count
                timeline_data['anomaly_counts'].append(row[2])  # anomaly_count
                timeline_data['confidence_scores'].append(0.8)  # Default confidence
            
            print(f"📊 Retrieved {len(rows)} time points for current session")
            return timeline_data
    
    def _empty_timeline_data(self):
        """Return empty timeline data structure"""
        return {
            'timestamps': [],
            'normal_counts': [],
            'anomaly_counts': [],
            'confidence_scores': []
        }
    
    async def get_session_threat_categories(self) -> Dict:
        """Get threat category distribution for current session"""
        if not self.current_session_id:
            return {'categories': [], 'counts': []}
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute('''
                SELECT 
                    threat_category,
                    COUNT(*) as count
                FROM session_detections 
                WHERE session_id = ? AND is_anomaly = 1
                GROUP BY threat_category
                ORDER BY count DESC
            ''', (self.current_session_id,))
            
            rows = await cursor.fetchall()
            
            if not rows:
                return {'categories': [], 'counts': []}
            
            categories = []
            counts = []
            
            category_names = {
                'failed_authentication': 'Failed Authentication',
                'off_hours_activity': 'Off-Hours Activity',
                'privilege_escalation': 'Privilege Escalation',
                'external_ip_access': 'External IP Access',
                'unusual_access_pattern': 'Unusual Access Pattern'
            }
            
            for row in rows:
                category_name = category_names.get(row[0], row[0].title())
                categories.append(category_name)
                counts.append(row[1])
            
            print(f"📊 Retrieved {len(categories)} threat categories for current session")
            return {'categories': categories, 'counts': counts}
    
    async def get_session_hourly_patterns(self) -> Dict:
        """Get hourly threat patterns for current session"""
        if not self.current_session_id:
            return self._empty_pattern_data()
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute('''
                SELECT 
                    strftime('%H', timestamp) as hour,
                    COUNT(*) as threat_count
                FROM session_detections 
                WHERE session_id = ? AND is_anomaly = 1
                GROUP BY strftime('%H', timestamp)
                ORDER BY hour
            ''', (self.current_session_id,))
            
            rows = await cursor.fetchall()
            
            # Create time period buckets
            hourly_patterns = {
                '00-03': 0, '03-06': 0, '06-09': 0, '09-12': 0,
                '12-15': 0, '15-18': 0, '18-21': 0, '21-24': 0
            }
            
            for row in rows:
                hour = int(row[0])
                if 0 <= hour < 3:
                    hourly_patterns['00-03'] += row[1]
                elif 3 <= hour < 6:
                    hourly_patterns['03-06'] += row[1]
                elif 6 <= hour < 9:
                    hourly_patterns['06-09'] += row[1]
                elif 9 <= hour < 12:
                    hourly_patterns['09-12'] += row[1]
                elif 12 <= hour < 15:
                    hourly_patterns['12-15'] += row[1]
                elif 15 <= hour < 18:
                    hourly_patterns['15-18'] += row[1]
                elif 18 <= hour < 21:
                    hourly_patterns['18-21'] += row[1]
                else:
                    hourly_patterns['21-24'] += row[1]
            
            return {
                'time_periods': list(hourly_patterns.keys()),
                'threat_counts': list(hourly_patterns.values())
            }
    
    def _empty_pattern_data(self):
        """Return empty pattern data structure"""
        return {
            'time_periods': ['00-03', '03-06', '06-09', '09-12', '12-15', '15-18', '18-21', '21-24'],
            'threat_counts': [0, 0, 0, 0, 0, 0, 0, 0]
        }
    
    async def get_session_statistics(self) -> Dict:
        """Get statistics for current session only"""
        if not self.current_session_id:
            return self._empty_stats()
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute('''
                SELECT 
                    COUNT(*) as total_logs,
                    SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as total_anomalies,
                    AVG(processing_time_ms) as avg_processing_time,
                    MAX(timestamp) as last_processed
                FROM session_detections
                WHERE session_id = ?
            ''', (self.current_session_id,))
            
            stats = await cursor.fetchone()
            
            return {
                'total_logs_processed': stats[0] or 0,
                'total_anomalies_detected': stats[1] or 0,
                'normal_activities': (stats[0] or 0) - (stats[1] or 0),
                'avg_processing_time_ms': round(stats[2] or 0, 2),
                'last_processed_time': stats[3],
                'threat_rate_percent': round(((stats[1] or 0) / max(stats[0], 1)) * 100, 2),
                'session_id': self.current_session_id
            }
    
    def _empty_stats(self):
        """Return empty statistics"""
        return {
            'total_logs_processed': 0,
            'total_anomalies_detected': 0,
            'normal_activities': 0,
            'avg_processing_time_ms': 0,
            'last_processed_time': None,
            'threat_rate_percent': 0,
            'session_id': None
        }

# Global database instance
db_manager = SessionBasedAnomalyDatabase()
