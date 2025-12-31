import re
from collections import Counter, defaultdict
import sys

class LogAnalyzer:
    def __init__(self):
        # Common Apache log format regex
        self.log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^"]*) HTTP/(?P<http_version>[\d.]+)" (?P<status>\d+) (?P<size>\d+) "(?P<re_referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )

        # Patterns for failed login detection
        self.failed_login_patterns = [
            re.compile(r'401'),  # HTTP 401 Unauthorized
            re.compile(r'failed login', re.IGNORECASE),
            re.compile(r'invalid credentials', re.IGNORECASE),
            re.compile(r'authentication failed', re.IGNORECASE)
        ]

    def parse_log_line(self, line):
        """Parse a single log line and return structured data."""
        match = self.log_pattern.match(line.strip())
        if match:
            return match.groupdict()
        return None

    def detect_failed_logins(self, logs):
        """Detect failed login attempts."""
        failed_attempts = []
        for log in logs:
            if log:
                # Check status code
                if log.get('status') == '401':
                    failed_attempts.append({
                        'ip': log['ip'],
                        'timestamp': log['timestamp'],
                        'reason': 'HTTP 401 Unauthorized'
                    })
                # Check for failed login patterns in path or user agent
                for pattern in self.failed_login_patterns[1:]:  # Skip 401 pattern
                    if pattern.search(log.get('path', '')) or pattern.search(log.get('user_agent', '')):
                        failed_attempts.append({
                            'ip': log['ip'],
                            'timestamp': log['timestamp'],
                            'reason': f'Pattern match: {pattern.pattern}'
                        })
        return failed_attempts

    def detect_unusual_traffic(self, logs, threshold=10):
        """Detect unusual traffic patterns."""
        ip_counter = Counter()
        path_counter = Counter()
        status_counter = Counter()

        for log in logs:
            if log:
                ip_counter[log['ip']] += 1
                path_counter[log['path']] += 1
                status_counter[log['status']] += 1

        # Identify IPs with high request counts
        suspicious_ips = {ip: count for ip, count in ip_counter.items() if count > threshold}

        # Identify frequently accessed paths
        suspicious_paths = {path: count for path, count in path_counter.items() if count > threshold}

        # Identify unusual status codes (high error rates)
        total_requests = len(logs)
        error_statuses = {'400', '401', '403', '404', '500', '502', '503'}
        error_rate = sum(status_counter.get(status, 0) for status in error_statuses) / total_requests if total_requests > 0 else 0

        return {
            'suspicious_ips': suspicious_ips,
            'suspicious_paths': suspicious_paths,
            'error_rate': error_rate,
            'high_error_rate': error_rate > 0.1  # More than 10% errors
        }

    def analyze_log_file(self, file_path):
        """Analyze a log file and return anomaly report."""
        logs = []
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    parsed_log = self.parse_log_line(line)
                    if parsed_log:
                        logs.append(parsed_log)
        except FileNotFoundError:
            print(f"Error: Log file '{file_path}' not found.")
            return None
        except Exception as e:
            print(f"Error reading log file: {e}")
            return None

        if not logs:
            print("No valid log entries found.")
            return None

        failed_logins = self.detect_failed_logins(logs)
        traffic_anomalies = self.detect_unusual_traffic(logs)

        return {
            'total_entries': len(logs),
            'failed_login_attempts': failed_logins,
            'traffic_anomalies': traffic_anomalies
        }

def main():
    if len(sys.argv) != 2:
        print("Usage: python Log_Analyser.py <log_file_path>")
        sys.exit(1)

    log_file = sys.argv[1]
    analyzer = LogAnalyzer()
    report = analyzer.analyze_log_file(log_file)

    if report:
        print("Log Analysis Report")
        print("=" * 50)
        print(f"Total log entries processed: {report['total_entries']}")
        print()

        print("Failed Login Attempts:")
        if report['failed_login_attempts']:
            for attempt in report['failed_login_attempts']:
                print(f"  - IP: {attempt['ip']}, Time: {attempt['timestamp']}, Reason: {attempt['reason']}")
        else:
            print("  No failed login attempts detected.")
        print()

        print("Traffic Anomalies:")
        anomalies = report['traffic_anomalies']
        if anomalies['suspicious_ips']:
            print("  Suspicious IPs (high request count):")
            for ip, count in anomalies['suspicious_ips'].items():
                print(f"    - {ip}: {count} requests")
        else:
            print("  No suspicious IPs detected.")

        if anomalies['suspicious_paths']:
            print("  Frequently accessed paths:")
            for path, count in anomalies['suspicious_paths'].items():
                print(f"    - {path}: {count} accesses")

        if anomalies['high_error_rate']:
            print(f"  High error rate detected: {anomalies['error_rate']:.2%}")
        else:
            print(f"  Error rate: {anomalies['error_rate']:.2%} (within normal range)")

if __name__ == "__main__":
    main()
