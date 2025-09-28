import logging
import json
import os
import sys

from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from storage.database import Database


app = Flask(__name__)
logger = logging.getLogger('api.server')
db = Database()

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'version': '1.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        start_time = request.args.get('start_time', (datetime.now() - timedelta(hours=24)).isoformat())
        end_time = request.args.get('end_time', datetime.now().isoformat())
        level = request.args.get('level', None)
        source = request.args.get('source', None)
        limit = int(request.args.get('limit', 100))
        conn = db._get_connection()
        cursor = conn.cursor()
        query = 'SELECT * FROM logs WHERE timestamp BETWEEN %s AND %s'
        params = [start_time, end_time]
        if level:
            query += ' AND level = %s'
            params.append(level)
        if source:
            query += ' AND source = %s'
            params.append(source)
        query += ' ORDER BY timestamp DESC LIMIT %s'
        params.append(limit)
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return jsonify({
            'count': len(results),
            'logs': results
        })
    except Exception as e:
        logger.error(f'Error fetching logs: {e}')
        return jsonify({'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        start_time = request.args.get('start_time', (datetime.now() - timedelta(hours=24)).isoformat())
        end_time = request.args.get('end_time', datetime.now().isoformat())
        severity = request.args.get('severity', None)
        rule_name = request.args.get('rule_name', None)
        limit = int(request.args.get('limit', 100))
        conn = db._get_connection()
        cursor = conn.cursor()
        query = 'SELECT * FROM alerts WHERE timestamp BETWEEN %s AND %s'
        params = [start_time, end_time]
        if severity:
            query += ' AND severity = %s'
            params.append(severity)
        if rule_name:
            query += ' AND rule_name = %s'
            params.append(rule_name)
        query += ' ORDER BY timestamp DESC LIMIT %s'
        params.append(limit)
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return jsonify({
            'count': len(results),
            'alerts': results
        })
    except Exception as e:
        logger.error(f'Error fetching alerts: {e}')
        return jsonify({'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
