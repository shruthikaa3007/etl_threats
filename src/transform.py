import pandas as pd
import re
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ThreatDataTransformer:
    def __init__(self):
        pass

    def validate_ip(self, ip):
        
        if not ip:
            logger.debug(f"Empty IP provided: {repr(ip)}")
            return False
        
      
        ip_str = str(ip).strip()
        
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip_str):
            parts = ip_str.split('.')
            try:
                is_valid = all(0 <= int(part) <= 255 for part in parts)
                if not is_valid:
                    logger.debug(f"Invalid IP values (out of range): {ip_str}")
                return is_valid
            except ValueError:
                logger.debug(f"Invalid IP format (non-numeric parts): {ip_str}")
                return False
        logger.debug(f"Invalid IP format (regex mismatch): {ip_str}")
        return False

    def standardize_abuseipdb_data(self, data):
     
        logger.info(f"Processing AbuseIPDB data: {len(data) if data else 0} items")
        
        if not data:
            logger.warning("No AbuseIPDB data provided")
            return []
        
       
        logger.debug(f"Sample AbuseIPDB item: {data[0] if data else 'None'}")
        
        standardized = []
        invalid_count = 0
        
        for i, item in enumerate(data):
            
            if i < 3:  
                logger.debug(f"AbuseIPDB item {i}: keys={list(item.keys()) if isinstance(item, dict) else 'Not a dict'}")
           
            ip = None
            for field in ['ipAddress', 'ip_address', 'ip', 'IP']:
                if item.get(field):
                    ip = item.get(field)
                    break
            
            if not self.validate_ip(ip):
                logger.debug(f"Skipping invalid AbuseIPDB IP: {repr(ip)} (item {i})")
                invalid_count += 1
                continue
                
            standard_item = {
                'ip_address': ip,
                'confidence_score': item.get('abuseConfidencePercentage', item.get('threat_score', 0)),
                'country_code': item.get('countryCode', 'Unknown'),
                'usage_type': item.get('usageType', 'Unknown'),
                'isp': item.get('isp', 'Unknown'),
                'last_reported': item.get('lastReportedAt'),
                'source': 'abuseipdb',
                'extracted_at': item.get('extracted_at'),
                'threat_score': item.get('abuseConfidencePercentage', item.get('threat_score', 0))
            }
            standardized.append(standard_item)

        logger.info(f"AbuseIPDB: {len(standardized)} valid records, {invalid_count} invalid/skipped")
        return standardized

    def standardize_otx_data(self, data):
        
        logger.info(f"Processing OTX data: {len(data) if data else 0} items")
        
        if not data:
            logger.warning("No OTX data provided")
            return []
        
        
        logger.debug(f"Sample OTX item: {data[0] if data else 'None'}")
        
        standardized = []
        invalid_count = 0
        
        for i, item in enumerate(data):
         
            if i < 3:  
                logger.debug(f"OTX item {i}: keys={list(item.keys()) if isinstance(item, dict) else 'Not a dict'}")
            
            ip = None
            for field in ['ip', 'ip_address', 'ipAddress', 'IP']:
                if item.get(field):
                    ip = item.get(field)
                    break
            
            if not self.validate_ip(ip):
                logger.debug(f"Skipping invalid OTX IP: {repr(ip)} (item {i})")
                invalid_count += 1
                continue
                
            confidence = item.get('confidence', 'medium')
            threat_score = 80 if confidence == 'high' else 50
            
            standard_item = {
                'ip_address': ip,
                'confidence_score': threat_score,
                'country_code': item.get('country_code', 'Unknown'),
                'usage_type': 'Unknown',
                'isp': item.get('isp', 'Unknown'),
                'last_reported': None,
                'source': 'otx',
                'extracted_at': item.get('extracted_at'),
                'threat_score': threat_score,
                'threat_type': item.get('threat_type', 'Unknown'),
                'pulse_id': item.get('pulse_id', None)
            }
            standardized.append(standard_item)

        logger.info(f"OTX: {len(standardized)} valid records, {invalid_count} invalid/skipped")
        return standardized

    def remove_duplicates(self, data):
        """Remove duplicate IP addresses, keeping highest threat score"""
        if not data:
            logger.warning("No data provided to deduplication step.")
            return []

        logger.info(f"Starting deduplication with {len(data)} records")
        
        df = pd.DataFrame(data)
        logger.debug(f"DataFrame columns: {list(df.columns)}")
        logger.debug(f"DataFrame shape: {df.shape}")
        
       
        if 'ip_address' not in df.columns:
            logger.error("Missing 'ip_address' column in data")
            return data
        
        if 'threat_score' not in df.columns:
            logger.warning("Missing 'threat_score' column, using confidence_score for deduplication")
            if 'confidence_score' in df.columns:
                df['threat_score'] = df['confidence_score']
            else:
                logger.error("No score column found for deduplication")
                return data
        
        initial_count = len(df)
        df_deduped = df.sort_values('threat_score', ascending=False).drop_duplicates('ip_address')
        final_count = len(df_deduped)
        
        logger.info(f"Deduplication complete: {initial_count} -> {final_count} records ({initial_count - final_count} duplicates removed)")
        return df_deduped.to_dict('records')

    def transform_data(self, abuseipdb_data, otx_data):
        """Main transformation function for AbuseIPDB and OTX"""
        logger.info(" Starting data transformation ")
        logger.info(f"Input - AbuseIPDB: {len(abuseipdb_data) if abuseipdb_data else 0} items")
        logger.info(f"Input - OTX: {len(otx_data) if otx_data else 0} items")

        
        if not abuseipdb_data and not otx_data:
            logger.error(" No input data provided to transform_data")
            return []
        
        if not abuseipdb_data:
            logger.warning("No AbuseIPDB data provided")
        
        if not otx_data:
            logger.warning(" No OTX data provided")

        try:
            std_abuse = self.standardize_abuseipdb_data(abuseipdb_data or [])
            std_otx = self.standardize_otx_data(otx_data or [])
        except Exception as e:
            logger.error(f" Standardization failed: {e}")
            logger.exception("Full error details:")
            return []

        combined_data = std_abuse + std_otx
        logger.info(f"Combined data: {len(std_abuse)} AbuseIPDB + {len(std_otx)} OTX = {len(combined_data)} total")

        if not combined_data:
            logger.error(" No valid records after standardization")
            return []

        try:
            clean_data = self.remove_duplicates(combined_data)
        except Exception as e:
            logger.error(f" Deduplication failed: {e}")
            logger.exception("Full error details:")
            clean_data = combined_data 
        logger.info(f"=== Transformation complete: {len(clean_data)} records ready for loading ===")
        
       
        if clean_data:
            logger.debug(f"Sample final record: {clean_data[0]}")
        
        return clean_data

    def debug_input_data(self, abuseipdb_data, otx_data):
     
        logger.info("DEBUG: Input Data Analysis ")
        
    
        if abuseipdb_data:
            logger.info(f"AbuseIPDB data type: {type(abuseipdb_data)}")
            logger.info(f"AbuseIPDB length: {len(abuseipdb_data)}")
            if len(abuseipdb_data) > 0:
                sample = abuseipdb_data[0]
                logger.info(f"AbuseIPDB sample type: {type(sample)}")
                if isinstance(sample, dict):
                    logger.info(f"AbuseIPDB sample keys: {list(sample.keys())}")
                    logger.info(f"AbuseIPDB sample values: {sample}")
                else:
                    logger.info(f"AbuseIPDB sample content: {sample}")
        else:
            logger.info("AbuseIPDB data: None or empty")
     
        if otx_data:
            logger.info(f"OTX data type: {type(otx_data)}")
            logger.info(f"OTX length: {len(otx_data)}")
            if len(otx_data) > 0:
                sample = otx_data[0]
                logger.info(f"OTX sample type: {type(sample)}")
                if isinstance(sample, dict):
                    logger.info(f"OTX sample keys: {list(sample.keys())}")
                    logger.info(f"OTX sample values: {sample}")
                else:
                    logger.info(f"OTX sample content: {sample}")
        else:
            logger.info("OTX data: None or empty")
        
        logger.info(" END DEBUG ")
