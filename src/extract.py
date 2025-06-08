from pymongo import MongoClient
import logging
import os
from dotenv import load_dotenv

load_dotenv('config/.env')
logger = logging.getLogger(__name__)

class ThreatDataLoader:
    def __init__(self):
        self.mongodb_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
        self.db_name = os.getenv('DATABASE_NAME', 'cyber_threats')
        self.collection_name = os.getenv('COLLECTION_NAME', 'threat_data')
        self.client = None
        self.db = None
        self.collection = None
        
    def connect(self):
       
        try:
            self.client = MongoClient(self.mongodb_uri)
            self.db = self.client[self.db_name]
            self.collection = self.db[self.collection_name]
            
         
            self.collection.create_index("ip_address", unique=True)
            self.collection.create_index("extracted_at")
            
            logger.info("Connected to MongoDB successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            return False
    
    def load_data(self, data):
        """Load data into MongoDB"""
        if not self.connect():
            return False
        
        try:
            
            for record in data:
                self.collection.replace_one(
                    {"ip_address": record["ip_address"]},
                    record,
                    upsert=True
                )
            
            logger.info(f"Successfully loaded {len(data)} records to MongoDB")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load data: {e}")
            return False
        
        finally:
            if self.client:
                self.client.close()
    
    def get_threat_data(self, limit=None):
        """Retrieve threat data from MongoDB"""
        if not self.connect():
            return []
        
        try:
            cursor = self.collection.find().sort("threat_score", -1)
            if limit:
                cursor = cursor.limit(limit)
            
            data = list(cursor)
            logger.info(f"Retrieved {len(data)} records from MongoDB")
            return data
            
        except Exception as e:
            logger.error(f"Failed to retrieve data: {e}")
            return []
        
        finally:
            if self.client:
                self.client.close()
