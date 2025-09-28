import re
import json
import datetime


class LogParser:
    def __init__(self, log_format='default'):
        self.log_format = log_format
        self.patterns = {
            'default': r'(?P<timestamp>.*?) (?P<level>\w+) (?P<message>.*)',
            'apache': r'(?P<ip>[\d.]+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\d+)',
            'syslog': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) (?P<application>\S+): (?P<message>.*)'
        }
    
    def parse(self, log_entry):
        try:
            pattern = self.patterns.get(self.log_format, self.patterns['default'])
            match = re.match(pattern, log_entry)
            if match:
                return match.groupdict()
            return {'raw': log_entry, 'timestamp': datetime.datetime.now().isoformat()}
        except Exception as e:
            return {'raw': log_entry, 'error': str(e)}
