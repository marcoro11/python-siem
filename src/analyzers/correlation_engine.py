import logging

from datetime import datetime, timedelta
from collections import defaultdict


logger = logging.getLogger('analyzers.correlation_engine')

class CorrelationRule:
    def __init__(self, id, name, description, severity='medium', timeframe_minutes=60):
        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
        self.timeframe_minutes = timeframe_minutes
        
    def evaluate(self, events):
        raise NotImplementedError('Subclasses must implement evaluate()')

class BruteForceRule(CorrelationRule):
    def __init__(self, threshold=5):
        super().__init__(
            id='CORR-001',
            name='Authentication Brute Force',
            description='Multiple failed authentication attempts from same source',
            severity='high',
            timeframe_minutes=15
        )
        self.threshold = threshold
        
    def evaluate(self, events):
        failed_auths = [e for e in events if 
                         'failed' in e.get('message', '').lower() and 
                         'login' in e.get('message', '').lower()]
        attempts_by_source = defaultdict(list)
        for event in failed_auths:
            import re
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', event.get('message', ''))
            if ip_match:
                source_ip = ip_match.group(1)
                attempts_by_source[source_ip].append(event)
        alerts = []
        for source_ip, attempts in attempts_by_source.items():
            if len(attempts) >= self.threshold:
                alerts.append({
                    'rule_id': self.id,
                    'rule_name': self.name,
                    'severity': self.severity,
                    'message': f'Possible brute force detected from {source_ip}: {len(attempts)} failed login attempts',
                    'source_ip': source_ip,
                    'count': len(attempts),
                    'matches': attempts,
                    'timestamp': datetime.now().isoformat()
                })
                
        return alerts

class CorrelationEngine:
    def __init__(self):
        self.rules = []
        self.event_buffer = []
        self.buffer_timeframe = timedelta(hours=1)
        
    def add_rule(self, rule):
        self.rules.append(rule)
        logger.info(f'Added correlation rule: {rule.name}')
        
    def add_events(self, events):
        current_time = datetime.now()
        for event in events:
            if isinstance(event, dict) and 'timestamp' in event:
                self.event_buffer.append(event)
            else:
                logger.debug(f'Skipping event without proper timestamp')
        cutoff_time = current_time - self.buffer_timeframe
        self.event_buffer = [
            e for e in self.event_buffer
            if datetime.fromisoformat(str(e['timestamp']).replace('Z', '+00:00')) > cutoff_time
        ]
        logger.debug(f'Event buffer size: {len(self.event_buffer)} events')
        
    def evaluate_rules(self):
        all_alerts = []
        for rule in self.rules:
            try:
                rule_timeframe = timedelta(minutes=rule.timeframe_minutes)
                cutoff_time = datetime.now() - rule_timeframe
                relevant_events = [
                    e for e in self.event_buffer
                    if datetime.fromisoformat(str(e['timestamp']).replace('Z', '+00:00')) > cutoff_time
                ]
                alerts = rule.evaluate(relevant_events)
                all_alerts.extend(alerts)
            except Exception as e:
                logger.error(f'Error evaluating rule {rule.id}: {e}')
        return all_alerts
