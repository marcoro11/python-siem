import re

from datetime import datetime, timedelta


class SecurityRule:
    def __init__(self, id, name, description, severity='medium'):
        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
    
    def evaluate(self, log):
        raise NotImplementedError('Subclasses must implement evaluate()')
    
    def matches(self, log):
        matched, _ = self.evaluate(log)
        return matched

class PrivilegeEscalationRule(SecurityRule):
    def __init__(self):
        super().__init__(
            id='RULE-001',
            name='privilege_escalation',
            description='Detects potential privilege escalation attempts',
            severity='high'
        )
    
    def evaluate(self, log):
        message = log.get('message', '').lower()
        if ('sudo su' in message or 
            'sudo -i' in message or 
            'sudo bash' in message or
            ('sudo' in message and ('chmod 777' in message or 'chown root' in message))):
            return True, 'Potential privilege escalation detected'
        return False, None

class SensitiveFileAccessRule(SecurityRule):
    def __init__(self):
        super().__init__(
            id='RULE-002',
            name='sensitive_file_access',
            description='Detects access to sensitive system files',
            severity='medium'
        )
        self.sensitive_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers', 
            '/etc/ssh', '/.ssh/id_rsa', '.bash_history'
        ]
    
    def evaluate(self, log):
        message = log.get('message', '')
        for file in self.sensitive_files:
            if file in message and ('access' in message.lower() or 'read' in message.lower() or 'modified' in message.lower()):
                return True, f'Sensitive file access detected: {file}'
        return False, None

class DataExfiltrationRule(SecurityRule):
    def __init__(self):
        super().__init__(
            id='RULE-003',
            name='data_exfiltration',
            description='Detects potential data exfiltration',
            severity='critical'
        )
    
    def evaluate(self, log):
        message = log.get('message', '').lower()
        if ('transfer' in message or 'download' in message or 'upload' in message) and ('gb' in message or 'mb' in message):
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.search(ip_pattern, message):
                return True, 'Potential data exfiltration detected'
        return False, None
