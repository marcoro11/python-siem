import psycopg2
import logging

from datetime import datetime, timedelta


logger = logging.getLogger('search.query_engine')

class SearchEngine:
    def __init__(self, db_config):
        self.db_config = db_config
        
    def _get_connection(self):
        return psycopg2.connect(
            host=self.db_config['host'],
            port=self.db_config['port'],
            dbname=self.db_config['dbname'],
            user=self.db_config['user'],
            password=self.db_config['password']
        )
        
    def search_logs(self, query_params):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            where_clauses = []
            params = []
            if 'start_time' in query_params:
                where_clauses.append('timestamp >= %s')
                params.append(query_params['start_time'])
            else:
                where_clauses.append('timestamp >= %s')
                params.append(datetime.now() - timedelta(hours=24))
            if 'end_time' in query_params:
                where_clauses.append('timestamp <= %s')
                params.append(query_params['end_time'])
            if 'level' in query_params:
                where_clauses.append('level = %s')
                params.append(query_params['level'])
            if 'source' in query_params:
                where_clauses.append('source = %s')
                params.append(query_params['source'])
            if 'message_contains' in query_params:
                where_clauses.append('message LIKE %s')
                params.append(f'%{query_params["message_contains"]}%')
            if 'host' in query_params:
                where_clauses.append('host = %s')
                params.append(query_params['host'])
            base_query = 'SELECT timestamp, source, level, message, host, process, raw_data FROM logs'
            if where_clauses:
                base_query += ' WHERE ' + ' AND '.join(where_clauses)
            base_query += ' ORDER BY timestamp DESC'
            limit = query_params.get('limit', 100)
            base_query += ' LIMIT %s'
            params.append(limit)
            cursor.execute(base_query, params)
            results = cursor.fetchall()
            columns = ['timestamp', 'source', 'level', 'message', 'host', 'process', 'raw_data']
            formatted_results = []
            for row in results:
                result = {}
                for i, col in enumerate(columns):
                    result[col] = row[i]
                formatted_results.append(result)
            return formatted_results
        except Exception as e:
            logger.error(f'Error executing search query: {e}')
            return []
        finally:
            if conn:
                conn.close()
                
    def search_alerts(self, query_params):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            where_clauses = []
            params = []
            if 'start_time' in query_params:
                where_clauses.append('timestamp >= %s')
                params.append(query_params['start_time'])
            else:
                where_clauses.append('timestamp >= %s')
                params.append(datetime.now() - timedelta(hours=24))
            if 'end_time' in query_params:
                where_clauses.append('timestamp <= %s')
                params.append(query_params['end_time'])
            if 'severity' in query_params:
                where_clauses.append('severity = %s')
                params.append(query_params['severity'])
            if 'rule_name' in query_params:
                where_clauses.append('rule_name = %s')
                params.append(query_params['rule_name'])
            if 'message_contains' in query_params:
                where_clauses.append('message LIKE %s')
                params.append(f'%{query_params["message_contains"]}%')
            base_query = 'SELECT timestamp, rule_name, severity, count, source, message FROM alerts'
            if where_clauses:
                base_query += ' WHERE ' + ' AND '.join(where_clauses)
            base_query += ' ORDER BY timestamp DESC'
            limit = query_params.get('limit', 100)
            base_query += ' LIMIT %s'
            params.append(limit)
            cursor.execute(base_query, params)
            results = cursor.fetchall()
            columns = ['timestamp', 'rule_name', 'severity', 'count', 'source', 'message']
            formatted_results = []
            for row in results:
                result = {}
                for i, col in enumerate(columns):
                    result[col] = row[i]
                formatted_results.append(result)
            return formatted_results
        except Exception as e:
            logger.error(f'Error executing alert search query: {e}')
            return []
        finally:
            if conn:
                conn.close()
