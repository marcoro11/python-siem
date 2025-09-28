import socket
import threading
import socketserver
import logging


logger = logging.getLogger('collectors.syslog_collector')

class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        self.server.received_logs.append(data.decode('utf-8', errors='ignore'))
        
class SyslogCollector:
    def __init__(self, host='0.0.0.0', port=514):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
        self.logs = []
        
    def start(self):
        if self.running:
            return
            
        class SyslogUDPServer(socketserver.UDPServer):
            received_logs = []
            
        try:
            self.server = SyslogUDPServer((self.host, self.port), SyslogHandler)
            self.server.received_logs = []
            self.thread = threading.Thread(target=self.server.serve_forever)
            self.thread.daemon = True
            self.thread.start()
            self.running = True
            logger.info(f'Syslog collector started on {self.host}:{self.port}')
        except Exception as e:
            logger.error(f'Failed to start syslog collector: {e}')
            
    def stop(self):
        if not self.running:
            return
        if self.server:
            self.server.shutdown()
            self.running = False
            logger.info('Syslog collector stopped')
    
    def collect(self):
        if not self.running:
            self.start()
            return []
        logs = self.server.received_logs.copy()
        self.server.received_logs.clear()
        return logs
