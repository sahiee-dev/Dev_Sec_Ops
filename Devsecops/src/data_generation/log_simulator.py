import random
import datetime
import json
import time

class SimpleLogGenerator:
    """
    This class creates fake logs that look like real computer logs.
    Think of it like a movie set - everything looks real but it's all fake!
    """
    
    def __init__(self):
        # These are our "actors" - fake users and actions
        self.users = ['john_doe', 'jane_smith', 'admin', 'backup_service', 'web_user']
        self.actions = ['login', 'logout', 'file_access', 'data_backup', 'system_check']
        self.ip_addresses = ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13']
        self.files = ['/home/docs/report.pdf', '/var/log/system.log', '/tmp/backup.zip']
        
    def generate_normal_log(self):
        """
        Create a log entry that represents normal, everyday computer activity.
        Like someone coming to work, checking email, saving files - normal stuff.
        """
        # Get the current time
        timestamp = datetime.datetime.now()
        
        # Pick random normal values
        user = random.choice(self.users)
        action = random.choice(self.actions)
        ip = random.choice(self.ip_addresses)
        
        # Create our log entry as a dictionary (like a form with fields)
        log_entry = {
            'timestamp': timestamp.isoformat(),  # Convert time to text
            'user': user,
            'action': action,
            'ip_address': ip,
            'status': 'success',
            'severity': 'info'
        }
        
        # Add extra details for some actions
        if action == 'file_access':
            log_entry['file'] = random.choice(self.files)
        
        return log_entry
    
    def generate_suspicious_log(self):
        """
        Create log entries that should trigger our anomaly detector.
        These represent potentially dangerous activity.
        """
        timestamp = datetime.datetime.now()
        
        # Create different types of suspicious activities
        suspicious_scenarios = [
            {
                'user': 'unknown_user', 
                'action': 'login_attempt', 
                'ip_address': '203.0.113.1',  # External IP
                'status': 'failed',
                'severity': 'warning',
                'reason': 'Unknown user from external IP'
            },
            {
                'user': 'admin', 
                'action': 'file_access', 
                'ip_address': '10.0.0.1',  # Admin from unusual location
                'status': 'success',
                'severity': 'warning',
                'file': '/etc/passwd',  # Sensitive system file
                'reason': 'Admin accessing sensitive files from unusual IP'
            },
            {
                'user': 'backup_service', 
                'action': 'data_backup', 
                'ip_address': '192.168.1.10',
                'status': 'success',
                'severity': 'error',
                'time_of_day': 'unusual',
                'reason': 'Backup service running at unusual time'
            }
        ]
        
        # Pick one suspicious scenario
        log_entry = random.choice(suspicious_scenarios)
        log_entry['timestamp'] = timestamp.isoformat()
        return log_entry
    
    def generate_batch_logs(self, normal_count=10, suspicious_count=2):
        """
        Generate a batch of logs - mostly normal with some suspicious ones mixed in.
        This simulates what real log monitoring would look like.
        """
        all_logs = []
        
        # Generate normal logs
        print(f"Generating {normal_count} normal logs...")
        for i in range(normal_count):
            all_logs.append(self.generate_normal_log())
            time.sleep(0.1)  # Small delay to make timestamps different
        
        # Generate suspicious logs
        print(f"Generating {suspicious_count} suspicious logs...")
        for i in range(suspicious_count):
            all_logs.append(self.generate_suspicious_log())
            time.sleep(0.1)
        
        # Shuffle them so suspicious ones aren't all at the end
        random.shuffle(all_logs)
        
        return all_logs

# Test our generator (this runs when you execute the file directly)
if __name__ == "__main__":
    print("🚀 Testing our Log Generator!")
    print("=" * 50)
    
    # Create an instance of our generator
    generator = SimpleLogGenerator()
    
    print("📝 Sample Normal Logs:")
    # Generate and display 3 normal logs
    for i in range(3):
        log = generator.generate_normal_log()
        print(f"Log {i+1}: {json.dumps(log, indent=2)}")
        print()
    
    print("🚨 Sample Suspicious Logs:")
    # Generate and display 2 suspicious logs
    for i in range(2):
        log = generator.generate_suspicious_log()
        print(f"Suspicious Log {i+1}: {json.dumps(log, indent=2)}")
        print()
    
    print("📊 Generating a batch of mixed logs...")
    batch = generator.generate_batch_logs(normal_count=5, suspicious_count=2)
    print(f"Generated {len(batch)} total logs!")
    
    print("\n✅ Log generator is working perfectly!")
