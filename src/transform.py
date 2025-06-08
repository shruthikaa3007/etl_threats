import pandas as pd
import re
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ThreatDataTransformer:
    def __init__(self):
        pass
    
    def validate_ip(self, ip):
        """Validate IP address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def standardize_abuseipdb_data(self, data):
        """Standardize AbuseIPDB data format"""
        standardized = []
        
        for item in data:
            if self.validate_ip(item.get('ipAddress', '')):
                standard_item = {
                    'ip_address': item.get('ipAddress'),
                    'confidence_score': item.get('abuseConfidencePercentage', 0),
                    'country_code': item.get('countryCode', 'Unknown'),
                    'usage_type': item.get('usageType', 'Unknown'),
                    'isp': item.get('isp', 'Unknown'),
                    'last_reported': item.get('lastReportedAt'),
                    'source': 'abuseipdb',
                    'extracted_at': item.get('extracted_at'),
                    'threat_score': item.get('abuseConfidencePercentage', 0)
                }
                standardized.append(standard_item)
        
        return standardized
    
    def standardize_virustotal_data(self, data):
        """Standardize VirusTotal data format"""
        standardized = []
        
        for item in data:
            if self.validate_ip(item.get('ip', '')):
                # Calculate threat score based on detections
                threat_score = min(100, (item.get('detected_urls', 0) * 10 + 
                                       item.get('detected_samples', 0) * 5))
                
                standard_item = {
                    'ip_address': item.get('ip'),
                    'confidence_score': threat_score,
                    'country_code': item.get('country', 'Unknown'),
                    'usage_type': 'Unknown',
                    'isp': item.get('as_owner', 'Unknown'),
                    'last_reported': datetime.now().isoformat(),
                    'source': 'virustotal',
                    'extracted_at': item.get('extracted_at'),
                    'threat_score': threat_score,
                    'detected_urls': item.get('detected_urls', 0),
                    'detected_samples': item.get('detected_samples', 0)
                }
                standardized.append(standard_item)
        
        return standardized
    
    def remove_duplicates(self, data):
        """Remove duplicate IP addresses, keeping highest threat score"""
        df = pd.DataFrame(data)
        if df.empty:
            return []
        
        # Sort by threat_score descending and drop duplicates by ip_address
        df_deduped = df.sort_values('threat_score', ascending=False).drop_duplicates('ip_address')
        
        logger.info(f"Removed {len(df) - len(df_deduped)} duplicate records")
        return df_deduped.to_dict('records')
    
    def transform_data(self, abuseipdb_data, virustotal_data):
        """Main transformation function"""
        logger.info("Starting data transformation...")
        
        # Standardize data from both sources
        std_abuse = self.standardize_abuseipdb_data(abuseipdb_data)
        std_vt = self.standardize_virustotal_data(virustotal_data)
        
        # Combine data
        combined_data = std_abuse + std_vt
        
        # Remove duplicates
        clean_data = self.remove_duplicates(combined_data)
        
        logger.info(f"Transformation complete. {len(clean_data)} records ready for loading.")
        return clean_data