import os
import logging


logger = logging.getLogger('collectors.file_collector')

class FileCollector:
    def __init__(self, log_path, polling_interval=10):
        self.log_path = log_path
        self.polling_interval = polling_interval
        self.last_position = {}
        
    def collect(self):
        if not os.path.exists(self.log_path):
            logger.warning(f'Log file not found: {self.log_path}')
            return []
        try:
            logs = []
            with open(self.log_path, 'r') as f:
                position = self.last_position.get(self.log_path, 0)
                f.seek(position)
                for line in f:
                    if line.strip():
                        logs.append(line.strip())
                self.last_position[self.log_path] = f.tell()
            if logs:
                logger.debug(f'Collected {len(logs)} new log entries from {self.log_path}')
            return logs
        except Exception as e:
            logger.error(f'Error collecting logs from {self.log_path}: {e}')
            return []
