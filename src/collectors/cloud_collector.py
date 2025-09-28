import boto3
import logging

from datetime import datetime, timedelta


logger = logging.getLogger('collectors.cloud_collector')

class CloudTrailCollector:
    def __init__(self, aws_region='us-east-1', lookback_hours=1):
        self.aws_region = aws_region
        self.lookback_hours = lookback_hours
        self.last_query_time = datetime.now() - timedelta(hours=lookback_hours)
        
    def collect(self):
        try:
            client = boto3.client('cloudtrail', region_name=self.aws_region)
            logs = []
            end_time = datetime.now()
            start_time = self.last_query_time
            response = client.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50
            )
            for event in response.get('Events', []):
                log_entry = {
                    'timestamp': event.get('EventTime', datetime.now()).isoformat(),
                    'source': 'aws_cloudtrail',
                    'event_name': event.get('EventName', ''),
                    'username': event.get('Username', ''),
                    'resources': [r.get('ResourceName') for r in event.get('Resources', [])],
                    'level': 'INFO',
                    'message': f'AWS API call: {event.get("EventName")} by {event.get("Username")}',
                    'raw': event
                }
                logs.append(log_entry)
            self.last_query_time = end_time
            logger.info(f'Collected {len(logs)} CloudTrail events')
            return logs
        except Exception as e:
            logger.error(f'Error collecting CloudTrail logs: {e}')
            return []
