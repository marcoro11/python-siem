import requests
import logging

from email.message import EmailMessage


logger = logging.getLogger('alert.notifier')

class Notifier:
    def __init__(self, config):
        self.config = config
        
    def send_email_alert(self, alert):
        logger.debug('Email alerts are disabled')
        return False
            
    def send_webhook_alert(self, alert):
        if 'webhook' not in self.config:
            return False
        try:
            response = requests.post(
                self.config['webhook']['url'],
                json={
                    'alert': alert['rule_name'],
                    'severity': alert['severity'],
                    'details': alert
                },
                headers=self.config['webhook'].get('headers', {})
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f'Failed to send webhook: {e}')
            return False
