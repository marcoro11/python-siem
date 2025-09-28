import csv
import logging
import psycopg2
import os

from datetime import datetime, timedelta


logger = logging.getLogger('storage.retention')

class RetentionManager:
    def __init__(self, db_config, log_retention_days=90, alert_retention_days=365):
        self.db_config = db_config
        self.log_retention_days = log_retention_days
        self.alert_retention_days = alert_retention_days
        
    def _get_connection(self):
        return psycopg2.connect(
            host=self.db_config['host'],
            port=self.db_config['port'],
            dbname=self.db_config['dbname'],
            user=self.db_config['user'],
            password=self.db_config['password']
        )
    
    def clean_old_data(self):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            log_cutoff = datetime.now() - timedelta(days=self.log_retention_days)
            alert_cutoff = datetime.now() - timedelta(days=self.alert_retention_days)
            cursor.execute('DELETE FROM logs WHERE timestamp < %s', (log_cutoff,))
            logs_deleted = cursor.rowcount
            logger.info(f'Deleted {logs_deleted} logs older than {self.log_retention_days} days')
            cursor.execute('DELETE FROM alerts WHERE timestamp < %s', (alert_cutoff,))
            alerts_deleted = cursor.rowcount
            logger.info(f'Deleted {alerts_deleted} alerts older than {self.alert_retention_days} days')
            conn.commit()
            return {
                'logs_deleted': logs_deleted,
                'alerts_deleted': alerts_deleted
            }
        except Exception as e:
            logger.error(f'Error cleaning old data: {e}')
            if conn:
                conn.rollback()
            return {
                'logs_deleted': 0,
                'alerts_deleted': 0,
                'error': str(e)
            }
        finally:
            if conn:
                conn.close()
                
    def archive_to_csv(self, archive_path):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            log_cutoff = datetime.now() - timedelta(days=self.log_retention_days)
            alert_cutoff = datetime.now() - timedelta(days=self.alert_retention_days)
            os.makedirs(archive_path, exist_ok=True)
            log_filename = os.path.join(archive_path, f'logs_archive_{datetime.now().strftime("%Y%m%d")}.csv')
            cursor.execute('SELECT * FROM logs WHERE timestamp < %s', (log_cutoff,))
            log_rows = cursor.fetchall()
            with open(log_filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([desc[0] for desc in cursor.description])
                writer.writerows(log_rows)
            logger.info(f'Archived {len(log_rows)} logs to {log_filename}')
            alert_filename = os.path.join(archive_path, f'alerts_archive_{datetime.now().strftime("%Y%m%d")}.csv')
            cursor.execute('SELECT * FROM alerts WHERE timestamp < %s', (alert_cutoff,))
            alert_rows = cursor.fetchall()
            with open(alert_filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([desc[0] for desc in cursor.description])
                writer.writerows(alert_rows)
            logger.info(f'Archived {len(alert_rows)} alerts to {alert_filename}')
            return {
                'logs_archived': len(log_rows),
                'alerts_archived': len(alert_rows),
                'log_filename': log_filename,
                'alert_filename': alert_filename
            }
        except Exception as e:
            logger.error(f'Error archiving data: {e}')
            return {
                'logs_archived': 0,
                'alerts_archived': 0,
                'error': str(e)
            }
        finally:
            if conn:
                conn.close()
