import requests
import logging
from datetime import datetime
import os
from dotenv import load_dotenv
import time

load_dotenv(os.path.join(os.path.dirname(__file__), '../config/.env'))


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDataExtractor:
    def __init__(self):
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.otx_key = os.getenv('OTX_API_KEY')
        self.otx_base_url = 'https://otx.alienvault.com/api/v1'

    def extract_abuseipdb_data(self, limit=50):
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
            raw_data = response.json().get('data', [])

            normalized = []
            for item in raw_data:
                normalized.append({
                    'ip_address': item.get('ipAddress'),
                    'country_code': item.get('countryCode', 'Unknown'),
                    'threat_score': item.get('abuseConfidenceScore', 0),
                    'source': 'abuseipdb',
                    'extracted_at': datetime.now().isoformat()
                })

            logger.info(f"Extracted {len(normalized)} records from AbuseIPDB")
            return normalized

        except Exception as e:
            logger.error(f"Error extracting from AbuseIPDB: {e}")
            return []

    def extract_otx_data(self, limit=20):
      
        headers = {
            'X-OTX-API-KEY': self.otx_key
        }
        url = f"{self.otx_base_url}/pulses/subscribed"
        results = []

        try:
            response = requests.get(url, headers=headers, params={'limit': limit})
            response.raise_for_status()
            data = response.json()

            for pulse in data.get('results', []):
                for indicator in pulse.get('indicators', []):
                    if indicator.get('type') == 'IPv4':
                        results.append({
                            'ip_address': indicator.get('indicator'),
                            'threat_type': pulse.get('name', 'Unknown'),
                            'confidence': indicator.get('role', 'medium'),
                            'source': 'otx',
                            'pulse_id': pulse.get('id'),
                            'extracted_at': datetime.now().isoformat()
                        })

            logger.info(f"Extracted {len(results)} records from OTX")
            return results

        except Exception as e:
            logger.error(f"Error extracting from OTX: {e}")
            return []

    def extract_all(self, limit=100):
      
        all_data = []

        abuse_data = self.extract_abuseipdb_data(limit=limit // 2)
        otx_data = self.extract_otx_data(limit=limit // 2)

        all_data.extend(abuse_data)
        all_data.extend(otx_data)

        logger.info(f"Total threats extracted: {len(all_data)}")
        return all_data
