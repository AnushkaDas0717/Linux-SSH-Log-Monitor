# SSH Brute Force Detector

A Python script that monitors SSH authentication logs to detect potential brute force attacks by analyzing failed login attempts.

## Features

- 🔍 **Real-time Analysis**: Parses `/var/log/auth.log` line by line
- 🕒 **Time Window Tracking**: Monitors failures within configurable time windows (default: 10 minutes)
- 🚨 **Alert System**: Triggers alerts when IP addresses exceed failure thresholds
- 📊 **Comprehensive Reporting**: Provides detailed summaries of suspicious activities
- 🛡️ **Multiple Attack Patterns**: Detects various SSH failure types:
  - Failed password attempts
  - Failed public key authentication
  - Invalid user attempts
  - Pre-authentication disconnections
- ⚡ **Performance Optimized**: Uses compiled regex patterns for fast processing
- 🔒 **Error Handling**: Graceful handling of permission issues and missing files

## Requirements

- Python 3.6+
- Linux system with SSH logging enabled
- Access to `/var/log/auth.log` (usually requires root privileges)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/ssh-brute-force-detector.git
cd ssh-brute-force-detector
```

2. Make the script executable:
```bash
chmod +x ssh_detector.py
```

## Usage

### Basic Usage

Run with default settings (5 failures in 10 minutes):
```bash
sudo python3 ssh_detector.py
```

### Advanced Usage

Customize threshold and time window:
```bash
# Alert after 3 failures in 5 minutes
sudo python3 ssh_detector.py --threshold 3 --time-window 5

# Use custom log file
python3 ssh_detector.py --log-file /path/to/custom/auth.log

# Show help
python3 ssh_detector.py --help
```

### Command Line Options

```
--log-file, -f      Path to auth.log file (default: /var/log/auth.log)
--threshold, -t     Number of failures to trigger alert (default: 5)
--time-window, -w   Time window in minutes to track failures (default: 10)
--version          Show version information
--help             Show help message
```

## Sample Output

```
📖 Reading log file: /var/log/auth.log
🔍 Threshold: 5 failures
⏰ Time window: 10 minutes
------------------------------------------------------------
🚨 ALERT: IP 192.168.1.100 has 6 failed attempts!
🚨 ALERT: IP 203.0.113.25 has 6 failed attempts!
🚨 ALERT: IP 198.51.100.10 has 5 failed attempts!

📊 Processing complete:
   Total lines processed: 1,234
   SSH-related lines: 156
   Unique IPs with failures: 5
   Alerts triggered: 3

============================================================
📋 SUMMARY OF FAILED SSH ATTEMPTS
============================================================
IP Address      Failures   Status
----------------------------------------
192.168.1.100   6          🚨 SUSPICIOUS
203.0.113.25    6          🚨 SUSPICIOUS  
198.51.100.10   5          🚨 SUSPICIOUS
198.51.100.42   2          📝 Monitoring
10.0.0.5        2          📝 Monitoring

🔍 TOP SUSPICIOUS IPs (showing recent attempts):
------------------------------------------------------------

1. IP: 192.168.1.100 (6 failures)
   2024-12-25 10:15:34: Dec 25 10:15:34 ubuntu sshd[12349]: Failed password for guest from 192.168.1.100...
   2024-12-25 10:15:37: Dec 25 10:15:37 ubuntu sshd[12350]: Failed password for ubuntu from 192.168.1.100...
```

## Testing

A sample auth.log file is provided for testing purposes. You can test the script without sudo privileges:

```bash
# Test with sample data
python3 ssh_detector.py --log-file sample_auth.log --threshold 3
```

## How It Works

1. **Log Parsing**: The script reads the auth.log file line by line
2. **Pattern Matching**: Uses regex patterns to identify SSH failure events
3. **Time Window Tracking**: Maintains a sliding window of recent failures per IP
4. **Threshold Detection**: Triggers alerts when IPs exceed the failure threshold
5. **Cleanup**: Automatically removes old entries outside the time window
6. **Reporting**: Provides comprehensive summaries and detailed analysis

## Detected Attack Patterns

The script recognizes these SSH attack indicators:

- `Failed password for [user] from [IP]`
- `Failed publickey for [user] from [IP]`
- `Invalid user [user] from [IP]`
- `Connection closed by authenticating user [user] [IP] [preauth]`
- `Disconnected from [IP] port [port] [preauth]`

## Security Considerations

- **Run with appropriate privileges**: The script needs read access to `/var/log/auth.log`
- **Regular monitoring**: Consider running this script periodically via cron
- **IP whitelisting**: You may want to exclude known good IPs from monitoring
- **Integration**: Consider integrating with fail2ban or similar tools for automated blocking

## Troubleshooting

### Permission Denied
```bash
# Run with sudo
sudo python3 ssh_detector.py
```

### File Not Found
```bash
# Check if auth.log exists
ls -la /var/log/auth.log

# On some systems, it might be named differently
ls -la /var/log/secure    # CentOS/RHEL
ls -la /var/log/messages  # Some distributions
```

### No SSH Events Found
- Ensure SSH is running and logging is enabled
- Check if SSH events are logged to a different file
- Verify the log format matches expected patterns

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v1.0 (2024-12-25)
- Initial release
- Support for multiple SSH failure patterns
- Configurable thresholds and time windows
- Comprehensive reporting and alerting
- Error handling and validation

## Future Enhancements

- [ ] Email/SMS notifications
- [ ] JSON output format
- [ ] Integration with fail2ban
- [ ] Geolocation lookup for IPs
- [ ] Web dashboard interface
- [ ] Machine learning-based anomaly detection
- [ ] Support for multiple log files
- [ ] Real-time monitoring mode

## Support

If you encounter any issues or have questions, please:

1. Check the troubleshooting section above
2. Search existing issues on GitHub
3. Create a new issue with detailed information about your problem

---

**⚠️ Disclaimer**: This tool is for monitoring and detection purposes only. Always ensure you comply with your organization's security policies and local laws when monitoring system logs.