import json
import psycopg2
import logging
import re

from datetime import datetime


logger = logging.getLogger('storage.database')

class Database:
    def __init__(self, db_path=None):
        self.db_config = {
            'host': 'localhost',
            'port': 5432,
            'dbname': 'siemdb',
            'user': 'siemuser',
            'password': 'siempassword'
        }
        logger.info(f'Initializing PostgreSQL connection to {self.db_config["host"]}:{self.db_config["port"]}')
        self.initialize_db()
        
    def _get_connection(self):
        return psycopg2.connect(
            host=self.db_config['host'],
            port=self.db_config['port'],
            dbname=self.db_config['dbname'],
            user=self.db_config['user'],
            password=self.db_config['password']
        )
        
    def initialize_db(self):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT column_name FROM information_schema.columns WHERE table_name=\'logs\' AND column_name=\'level\'')
            has_new_logs_schema = cursor.fetchone() is not None
            cursor.execute('SELECT column_name FROM information_schema.columns WHERE table_name=\'alerts\' AND column_name=\'source\'')
            has_new_alerts_schema = cursor.fetchone() is not None
            if not has_new_logs_schema:
                cursor.execute('DROP TABLE IF EXISTS logs')
                logger.info('Dropped old logs table structure')
            if not has_new_alerts_schema:
                cursor.execute('DROP TABLE IF EXISTS alerts')
                logger.info('Dropped old alerts table structure')
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                source TEXT,
                level TEXT,
                message TEXT,
                host TEXT,
                process TEXT,
                raw_data TEXT
            )
            ''')
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                rule_name TEXT,
                severity TEXT,
                count INTEGER,
                source TEXT,
                message TEXT,
                raw_details TEXT
            )
            ''')
            conn.commit()
            logger.info('PostgreSQL tables initialized successfully')
        except Exception as e:
            logger.error(f'Error initializing database: {e}')
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
        
    def store_logs(self, logs, source):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            for log in logs:
                timestamp = datetime.now()
                level = ''
                message = ''
                host = ''
                process = ''
                raw_data = ''
                if isinstance(log, dict):
                    if 'timestamp' in log:
                        try:
                            timestamp = datetime.fromisoformat(str(log['timestamp']).replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            pass
                    level = log.get('level', log.get('severity', ''))
                    message = log.get('message', log.get('msg', ''))
                    host = log.get('host', log.get('hostname', ''))
                    process = log.get('process', log.get('service', ''))
                    raw_data = json.dumps(log)
                else:
                    message = str(log)
                    raw_data = str(log)
                    try:
                        match = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)', message)
                        if match:
                            try:
                                timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
                                level = match.group(2)
                                message = match.group(3)
                            except (ValueError, IndexError):
                                pass
                    except Exception:
                        pass
                cursor.execute(
                    '''INSERT INTO logs 
                       (timestamp, source, level, message, host, process, raw_data) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                    (timestamp, source, level, message, host, process, raw_data)
                )
            conn.commit()
            logger.debug(f'Stored {len(logs)} logs from {source}')
        except Exception as e:
            logger.error(f'Error storing logs: {e}')
            if conn:
                conn.rollback()
        finally:
            if conn:
                conn.close()
        
    def store_alerts(self, alerts):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            total_inserted = 0
            for alert in alerts:
                rule_name = alert.get('rule_name', '')
                severity = alert.get('severity', 'medium')
                if 'matches' in alert and alert['matches'] and isinstance(alert['matches'], list):
                    for match in alert['matches']:
                        if isinstance(match, dict):
                            timestamp = datetime.now()
                            if 'timestamp' in match and match['timestamp']:
                                try:
                                    timestamp = datetime.fromisoformat(str(match['timestamp']).replace('Z', '+00:00'))
                                except (ValueError, TypeError):
                                    pass
                            source = match.get('source', '')
                            message = match.get('message', str(match))
                        else:
                            timestamp = datetime.now()
                            if isinstance(alert.get('timestamp'), str) and alert.get('timestamp'):
                                try:
                                    timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                                except (ValueError, TypeError):
                                    pass
                            source = ''
                            message = str(match)
                        cursor.execute(
                            '''INSERT INTO alerts 
                            (timestamp, rule_name, severity, count, source, message, raw_details) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                            (timestamp, rule_name, severity, 1, source, message, json.dumps(match))
                        )
                        total_inserted += 1
                else:
                    timestamp = datetime.now()
                    if isinstance(alert.get('timestamp'), str) and alert.get('timestamp'):
                        try:
                            timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            pass
                    source = alert.get('source', '')
                    message = alert.get('message', '')
                    count = alert.get('count', 0)
                    cursor.execute(
                        '''INSERT INTO alerts 
                        (timestamp, rule_name, severity, count, source, message, raw_details) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                        (timestamp, rule_name, severity, count, source, message, json.dumps(alert))
                    )
                    total_inserted += 1
            conn.commit()
            logger.info(f'Stored {total_inserted} individual alerts')
        except Exception as e:
            logger.error(f'Error storing alerts: {e}')
            if conn:
                conn.rollback()
        finally:
            if conn:
                conn.close()
