import logging

from collections import Counter
from .rules import PrivilegeEscalationRule, SensitiveFileAccessRule, DataExfiltrationRule


logger = logging.getLogger('analyzers.anomaly_detector')

class AnomalyDetector:
    def __init__(self, threshold=5):
        self.threshold = threshold
        self.rules = []
        self.rules.append(PrivilegeEscalationRule())
        self.rules.append(SensitiveFileAccessRule())
        self.rules.append(DataExfiltrationRule())
    
    def add_rule(self, rule):
        self.rules.append(rule)
    
    def analyze(self, log_entries):
        alerts = []
        for rule in self.rules:
            matches = [entry for entry in log_entries if rule.matches(entry)]
            if len(matches) > self.threshold:
                alerts.append({
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'matches': matches,
                    'count': len(matches)
                })
        return alerts

class Rule:
    def __init__(self, name, pattern, severity='medium'):
        self.name = name
        self.pattern = pattern
        self.severity = severity
    
    def matches(self, log_entry):
        if 'message' in log_entry and self.pattern in log_entry['message']:
            return True
        return False
