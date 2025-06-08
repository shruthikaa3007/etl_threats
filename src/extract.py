import requests
import time
import logging
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('config/.env')

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDataExtractor:
    def __init__(self):
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        
    def extract_abuseipdb_data(self, days=7, limit=50):
        """Extract data from AbuseIPDB API"""
        url = 'https://api.abuseipdb.com/api/v2/blacklist'
        headers = {
            'Key': self.abuseipdb_key,
            'Accept': 'application/json'
        }
        params = {
            'confidenceMinimum': 75,
            'limit': limit
        }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Add source and timestamp
            for item in data.get('data', []):
                item['source'] = 'abuseipdb'
                item['extracted_at'] = datetime.now().isoformat()
                
            logger.info(f"Extracted {len(data.get('data', []))} records from AbuseIPDB")
            return data.get('data', [])
            
        except Exception as e:
            logger.error(f"Error extracting from AbuseIPDB: {e}")
            return []
    
    def extract_virustotal_data(self, limit=50):
        """Extract data from VirusTotal API (using IP search)"""
        # For demo purposes, we'll use a list of known malicious IPs
        # In real implementation, you'd use VirusTotal's feed API
        sample_ips = [
            '185.220.101.182', '198.96.155.3', '23.129.64.131',
            '185.220.102.8', '192.42.116.16', '199.87.154.255'
        ]
        
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        results = []
        
        for ip in sample_ips[:limit]:
            params = {
                'apikey': self.virustotal_key,
                'ip': ip
            }
            
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                if data.get('response_code') == 1:
                    processed_data = {
                        'ip': ip,
                        'detected_urls': len(data.get('detected_urls', [])),
                        'detected_samples': len(data.get('detected_samples', [])),
                        'source': 'virustotal',
                        'extracted_at': datetime.now().isoformat(),
                        'country': data.get('country', 'Unknown'),
                        'as_owner': data.get('as_owner', 'Unknown')
                    }
                    results.append(processed_data)
                    
                # Rate limiting
                time.sleep(15)  # VirusTotal free API limit
                
            except Exception as e:
                logger.error(f"Error extracting {ip} from VirusTotal: {e}")
                continue
        
        logger.info(f"Extracted {len(results)} records from VirusTotal")
        return results