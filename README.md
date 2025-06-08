# Cyber Threat ETL Pipeline

An automated ETL pipeline that aggregates cybersecurity threat intelligence data from AbuseIPDB and OTX (Open Threat Exchange) APIs, processes the data, and stores it in MongoDB for analysis and reporting.

## Project Overview

This project implements a complete ETL (Extract, Transform, Load) pipeline that:
- Extracts threat data from two APIs (AbuseIPDB and OTX AlienVault)
- Cleans and standardizes the data
- Stores processed data in MongoDB with proper indexing
- Generates analysis reports with visualizations

## Requirements

```bash
pip install requests pymongo pandas matplotlib seaborn python-dotenv jupyter
```


## How to Run

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up API keys** in `config/.env`

3. **Start MongoDB** (if using local)

4. **Run the pipeline:**
   ```bash
   jupyter lab
   # Open notebooks/main_pipeline.ipynb and run all cells
   ```

## Pipeline Process

1. **Extract:** Fetches threat data from AbuseIPDB and OTX AlienVault APIs
2. **Transform:** 
   - Validates IP addresses
   - Removes duplicates
   - Standardizes data format across sources
3. **Load:** Stores data in MongoDB with indexing on IP addresses
4. **Analyze:** 
   - Identifies top 5 malicious IPs
   - Shows daily threat trends
   - Creates visualizations

## Output

The pipeline generates:
- **Top 5 malicious IPs** by threat score
- **Daily threat trends** over the past week
- **Visualizations** (bar charts and pie charts)
- **Summary report** in markdown format

## Key Challenges

1. **API Rate Limiting:** Implemented delays between requests to handle rate limits
2. **Data Inconsistency:** Created standardization functions to unify data from different sources
3. **Duplicate Handling:** Developed logic to keep highest threat score when IPs appear multiple times
4. **Error Handling:** Added comprehensive logging and error handling for API failures

## Technical Features

- **Modular Design:** Separate modules for each ETL phase
-  **MongoDB Indexing:** Efficient querying with indexed IP addresses
-  **Data Validation:** IP address format validation
-  **Automatic Deduplication:** Removes duplicate IPs while preserving highest threat scores
 - **Comprehensive Logging:** Detailed logs for debugging and monitoring




**Common Issues:**
-  **API Key Error:** Verify keys in .env file
-  **MongoDB Connection:** Check if MongoDB is running
-  **Rate Limiting:** Pipeline includes automatic delays for API limits
 - **Missing Data:** Some APIs  return empty results 

