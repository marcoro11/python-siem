import os
import time
import yaml
import logging
import threading

from datetime import datetime
from collectors.file_collector import FileCollector
from collectors.syslog_collector import SyslogCollector
from parsers.log_parser import LogParser
from analyzers.anomaly_detector import AnomalyDetector, Rule
from analyzers.correlation_engine import CorrelationEngine, BruteForceRule
from storage.database import Database
from storage.retention import RetentionManager
from enrichment.threat_intel import ThreatIntelligence
from alert.notifier import Notifier
from api.server import app as api_app


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('siem.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('siem')

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.yaml')
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

def run_api_server():
    api_app.run(host='0.0.0.0', port=5000)

def main():
    logger.info('Starting SIEM application')
    config = load_config()
    logger.info('Configuration loaded')
    collectors = []
    for log_file in config.get('log_files', []):
        collectors.append(FileCollector(log_file['path']))
    if config.get('enable_syslog', False):
        collectors.append(SyslogCollector(
            host=config['syslog']['host'],
            port=config['syslog']['port']
        ))
    parser = LogParser(log_format=config.get('log_format', 'default'))
    detector = AnomalyDetector(threshold=config.get('alert_threshold', 5))
    for rule_config in config.get('rules', []):
        rule = Rule(
            name=rule_config['name'],
            pattern=rule_config['pattern'],
            severity=rule_config.get('severity', 'medium')
        )
        detector.add_rule(rule)
    correlation_engine = CorrelationEngine()
    correlation_engine.add_rule(BruteForceRule(threshold=3))
    threat_intel = ThreatIntelligence()
    db = Database()
    retention_mgr = RetentionManager(db.db_config, 
                                     log_retention_days=config.get('log_retention_days', 90),
                                     alert_retention_days=config.get('alert_retention_days', 365))
    notifier = Notifier(config)
    logger.info('Components initialized')
    logger.info(f'Starting to monitor these files: {[c.log_path for c in collectors if hasattr(c, "log_path")]}')
    if config.get('enable_api', True):
        api_thread = threading.Thread(target=run_api_server, daemon=True)
        api_thread.start()
        logger.info('API server started on port 5000')
    last_retention_check = datetime.now()
    retention_interval = config.get('retention_check_hours', 24) * 3600
    try:
        while True:
            all_parsed_logs = []
            for collector in collectors:
                logs = collector.collect()
                if logs:
                    logger.info(f'Collected {len(logs)} logs from {collector.__class__.__name__}')
                    parsed_logs = []
                    for log in logs:
                        parsed_log = parser.parse(log)
                        parsed_logs.append(parsed_log)
                    db.store_logs(parsed_logs, collector.__class__.__name__)
                    all_parsed_logs.extend(parsed_logs)
            if all_parsed_logs:
                for log in all_parsed_logs:
                    import re
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(log.get('message', '')))
                    if ip_match:
                        ip = ip_match.group(1)
                        ti_result = threat_intel.check_ip(ip)
                        log['threat_intel'] = ti_result
                correlation_engine.add_events(all_parsed_logs)
                alerts = detector.analyze(all_parsed_logs)
                correlation_alerts = correlation_engine.evaluate_rules()
                alerts.extend(correlation_alerts)
                if alerts:
                    logger.info(f'Generated {len(alerts)} alerts')
                    db.store_alerts(alerts)
                    for alert in alerts:
                        if alert.get('severity') == 'high':
                            notifier.send_webhook_alert(alert)
            now = datetime.now()
            if (now - last_retention_check).total_seconds() > retention_interval:
                logger.info('Running data retention check')
                retention_result = retention_mgr.clean_old_data()
                logger.info(f'Retention check completed: deleted {retention_result.get("logs_deleted", 0)} logs and {retention_result.get("alerts_deleted", 0)} alerts')
                last_retention_check = now
            time.sleep(config.get('polling_interval', 30))
    except KeyboardInterrupt:
        logger.info('SIEM application stopped by user')
    except Exception as e:
        logger.error(f'Error in main loop: {e}', exc_info=True)
        
if __name__ == '__main__':
    main()
