#!/usr/bin/env python3
"""
SSH Brute Force Detector

This script monitors /var/log/auth.log for failed SSH login attempts
and detects potential brute force attacks by tracking IP addresses
that exceed a failure threshold within a time window.

Author: Your Name
License: MIT
"""

import re
import sys
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path


class SSHFailureDetector:
    """
    A class to detect SSH brute force attempts by analyzing auth.log files.
    """
    
    def __init__(self, log_file='/var/log/auth.log', threshold=5, time_window=10):
        """
        Initialize the SSH failure detector.
        
        Args:
            log_file (str): Path to the auth.log file
            threshold (int): Number of failures to trigger an alert
            time_window (int): Time window in minutes to track failures
        """
        self.log_file = Path(log_file)
        self.threshold = threshold
        self.time_window = timedelta(minutes=time_window)
        
        # Dictionary to store IP addresses and their failure attempts
        # Structure: {ip: [(timestamp, line), ...]}
        self.failed_attempts = defaultdict(list)
        
        # Regex patterns for different SSH failure types
        self.failure_patterns = [
            # Standard failed password attempts
            r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
            # Failed publickey attempts
            r'Failed publickey for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
            # Connection closed by authenticating user
            r'Connection closed by authenticating user \w+ (\d+\.\d+\.\d+\.\d+)',
            # Invalid user attempts
            r'Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)',
            # Preauth failures
            r'Disconnected from (\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]'
        ]
        
        # Compiled regex patterns for better performance
        self.compiled_patterns = [re.compile(pattern) for pattern in self.failure_patterns]
    
    def parse_timestamp(self, log_line):
        """
        Extract timestamp from log line.
        
        Args:
            log_line (str): A line from the auth.log file
            
        Returns:
            datetime: Parsed timestamp or None if parsing fails
        """
        try:
            # Standard syslog format: "MMM DD HH:MM:SS"
            # Example: "Dec 25 14:30:22"
            timestamp_match = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log_line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                # Add current year since syslog doesn't include it
                current_year = datetime.now().year
                timestamp_with_year = f"{current_year} {timestamp_str}"
                return datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
        except ValueError as e:
            print(f"Warning: Could not parse timestamp from line: {log_line[:50]}...")
            return None
        
        return None
    
    def extract_ip_from_line(self, line):
        """
        Extract IP address from a log line using regex patterns.
        
        Args:
            line (str): Log line to analyze
            
        Returns:
            str or None: IP address if found, None otherwise
        """
        for pattern in self.compiled_patterns:
            match = pattern.search(line)
            if match:
                # Different patterns have IP in different groups
                groups = match.groups()
                for group in groups:
                    # Check if this group looks like an IP address
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', group):
                        return group
        return None
    
    def is_ssh_failure(self, line):
        """
        Check if a log line represents an SSH failure.
        
        Args:
            line (str): Log line to check
            
        Returns:
            bool: True if line indicates SSH failure
        """
        failure_indicators = [
            'Failed password',
            'Failed publickey',
            'Invalid user',
            'Connection closed by authenticating user',
            'preauth'
        ]
        
        return any(indicator in line for indicator in failure_indicators)
    
    def clean_old_attempts(self, current_time):
        """
        Remove attempts that are outside the time window.
        
        Args:
            current_time (datetime): Current timestamp to compare against
        """
        cutoff_time = current_time - self.time_window
        
        for ip in list(self.failed_attempts.keys()):
            # Filter out old attempts
            self.failed_attempts[ip] = [
                (timestamp, line) for timestamp, line in self.failed_attempts[ip]
                if timestamp and timestamp > cutoff_time
            ]
            
            # Remove IP if no recent attempts
            if not self.failed_attempts[ip]:
                del self.failed_attempts[ip]
    
    def process_log_file(self):
        """
        Process the auth.log file and detect failed SSH attempts.
        
        Returns:
            dict: Summary of all failed attempts by IP
        """
        try:
            # Check if file exists and is readable
            if not self.log_file.exists():
                raise FileNotFoundError(f"Log file not found: {self.log_file}")
            
            if not self.log_file.is_file():
                raise ValueError(f"Path is not a file: {self.log_file}")
            
            print(f"📖 Reading log file: {self.log_file}")
            print(f"🔍 Threshold: {self.threshold} failures")
            print(f"⏰ Time window: {self.time_window.seconds // 60} minutes")
            print("-" * 60)
            
            alerts_triggered = []
            total_lines = 0
            ssh_lines = 0
            
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    total_lines += 1
                    line = line.strip()
                    
                    # Skip empty lines
                    if not line:
                        continue
                    
                    # Check if this line is SSH-related
                    if 'ssh' not in line.lower():
                        continue
                    
                    ssh_lines += 1
                    
                    # Check if this is a failure line
                    if not self.is_ssh_failure(line):
                        continue
                    
                    # Extract timestamp and IP
                    timestamp = self.parse_timestamp(line)
                    ip_address = self.extract_ip_from_line(line)
                    
                    if not ip_address:
                        continue
                    
                    # Add this attempt to our tracking
                    self.failed_attempts[ip_address].append((timestamp, line))
                    
                    # Clean old attempts if we have a valid timestamp
                    if timestamp:
                        self.clean_old_attempts(timestamp)
                    
                    # Check if this IP has exceeded the threshold
                    recent_failures = len(self.failed_attempts[ip_address])
                    if recent_failures >= self.threshold:
                        alert_key = (ip_address, recent_failures)
                        if alert_key not in alerts_triggered:
                            print(f"🚨 ALERT: IP {ip_address} has {recent_failures} failed attempts!")
                            alerts_triggered.append(alert_key)
            
            print(f"\n📊 Processing complete:")
            print(f"   Total lines processed: {total_lines:,}")
            print(f"   SSH-related lines: {ssh_lines:,}")
            print(f"   Unique IPs with failures: {len(self.failed_attempts)}")
            print(f"   Alerts triggered: {len(alerts_triggered)}")
            
            return dict(self.failed_attempts)
            
        except PermissionError:
            print(f"❌ Permission denied: Cannot read {self.log_file}")
            print("💡 Try running with sudo: sudo python3 ssh_detector.py")
            sys.exit(1)
        except FileNotFoundError as e:
            print(f"❌ File not found: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            sys.exit(1)
    
    def print_summary(self, failed_attempts):
        """
        Print a summary of all failed attempts.
        
        Args:
            failed_attempts (dict): Dictionary of IP addresses and their attempts
        """
        print("\n" + "="*60)
        print("📋 SUMMARY OF FAILED SSH ATTEMPTS")
        print("="*60)
        
        if not failed_attempts:
            print("✅ No failed SSH attempts detected within the time window.")
            return
        
        # Sort IPs by number of failures (descending)
        sorted_ips = sorted(
            failed_attempts.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        
        print(f"{'IP Address':<15} {'Failures':<10} {'Status'}")
        print("-" * 40)
        
        for ip, attempts in sorted_ips:
            failure_count = len(attempts)
            status = "🚨 SUSPICIOUS" if failure_count >= self.threshold else "📝 Monitoring"
            print(f"{ip:<15} {failure_count:<10} {status}")
        
        # Show top 3 most problematic IPs with sample log lines
        print(f"\n🔍 TOP SUSPICIOUS IPs (showing recent attempts):")
        print("-" * 60)
        
        for i, (ip, attempts) in enumerate(sorted_ips[:3]):
            if len(attempts) >= self.threshold:
                print(f"\n{i+1}. IP: {ip} ({len(attempts)} failures)")
                # Show last 2 attempts
                for timestamp, line in attempts[-2:]:
                    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else "Unknown time"
                    print(f"   {timestamp_str}: {line[:80]}...")


def main():
    """
    Main function to run the SSH failure detector.
    """
    parser = argparse.ArgumentParser(
        description='Detect SSH brute force attempts from auth.log',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ssh_detector.py
  python3 ssh_detector.py --threshold 3 --time-window 5
  sudo python3 ssh_detector.py --log-file /var/log/auth.log
        """
    )
    
    parser.add_argument(
        '--log-file', '-f',
        default='/var/log/auth.log',
        help='Path to auth.log file (default: /var/log/auth.log)'
    )
    
    parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=5,
        help='Number of failures to trigger alert (default: 5)'
    )
    
    parser.add_argument(
        '--time-window', '-w',
        type=int,
        default=10,
        help='Time window in minutes to track failures (default: 10)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SSH Brute Force Detector v1.0'
    )
    
    args = parser.parse_args()
    
    # Create detector instance
    detector = SSHFailureDetector(
        log_file=args.log_file,
        threshold=args.threshold,
        time_window=args.time_window
    )
    
    # Process the log file
    failed_attempts = detector.process_log_file()
    
    # Print summary
    detector.print_summary(failed_attempts)


if __name__ == '__main__':
    main()