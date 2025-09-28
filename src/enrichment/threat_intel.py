import requests
import json
import os
import logging
import ipaddress

from datetime import datetime, timedelta


logger = logging.getLogger('enrichment.threat_intel')

class ThreatIntelligence:
    def __init__(self, cache_file='threat_intel_cache.json', cache_hours=24):
        self.cache_file = cache_file
        self.cache_hours = cache_hours
        self.cache = self._load_cache()
        
    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                if datetime.fromisoformat(cache.get('timestamp', '2000-01-01')) > datetime.now() - timedelta(hours=self.cache_hours):
                    return cache
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f'Error loading cache: {e}')
        return {'timestamp': datetime.now().isoformat(), 'data': {}}
        
    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f'Error saving cache: {e}')
    
    def check_ip(self, ip):
        if ip in self.cache['data']:
            logger.debug(f'IP {ip} found in cache')
            return self.cache['data'][ip]
        try:
            self._update_blocklists_if_needed()
            matches = []
            score = 0
            ip_obj = ipaddress.ip_address(ip)
            if self._is_in_list(ip, 'tor_exit_nodes.txt'):
                matches.append('tor_exit_node')
                score += 50
            if self._is_in_list(ip, 'botnet_ips.txt'):
                matches.append('botnet')
                score += 80
            if self._is_in_cidr_list(ip_obj, 'spamhaus_drop.txt'):
                matches.append('spamhaus')
                score += 70
            is_malicious = score > 50
            result = {
                'is_malicious': is_malicious,
                'score': score,
                'matches': matches,
                'source': 'local_blocklists'
            }
            self.cache['data'][ip] = result
            self._save_cache()
            return result
        except Exception as e:
            logger.error(f'Error checking threat intelligence: {e}')
            return {'is_malicious': False, 'score': 0, 'source': 'error'}
        
    def _is_in_list(self, ip, filename):
        try:
            list_file = os.path.join('data', 'blocklists', filename)
            if not os.path.exists(list_file):
                return False
            with open(list_file, 'r') as f:
                return ip in [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            return False

    def _is_in_cidr_list(self, ip_obj, filename):
        try:
            list_file = os.path.join('data', 'blocklists', filename)
            if not os.path.exists(list_file):
                return False
            with open(list_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    try:
                        network = ipaddress.ip_network(line)
                        if ip_obj in network:
                            return True
                    except ValueError:
                        continue
            return False
        except Exception:
            return False
        
    def _update_blocklists_if_needed(self):
        blocklist_dir = os.path.join('data', 'blocklists')
        os.makedirs(blocklist_dir, exist_ok=True)
        blocklists = {
            'tor_exit_nodes.txt': 'https://check.torproject.org/exit-addresses',
            'botnet_ips.txt': 'https://urlhaus.abuse.ch/downloads/text/',
            'spamhaus_drop.txt': 'https://www.spamhaus.org/drop/drop.txt'
        }
        for filename, url in blocklists.items():
            file_path = os.path.join(blocklist_dir, filename)
            if not os.path.exists(file_path) or \
               datetime.fromtimestamp(os.path.getmtime(file_path)) < datetime.now() - timedelta(hours=24):
                try:
                    logger.info(f'Downloading blocklist: {filename}')
                    response = requests.get(url)
                    if response.status_code == 200:
                        if filename == 'tor_exit_nodes.txt':
                            ips = []
                            for line in response.text.splitlines():
                                if line.startswith('ExitAddress '):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        ips.append(parts[1])
                            with open(file_path, 'w') as f:
                                f.write('\n'.join(ips))
                        else:
                            with open(file_path, 'w') as f:
                                f.write(response.text)
                        logger.info(f'Updated blocklist: {filename}')
                    else:
                        logger.error(f'Failed to download {filename}: Status code {response.status_code}')
                except Exception as e:
                    logger.error(f'Error updating blocklist {filename}: {e}')
