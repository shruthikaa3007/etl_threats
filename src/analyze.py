import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self, data):
        self.df = pd.DataFrame(data)

    def get_top_malicious_ips(self, top_n=5):
        if self.df.empty:
            return []
        top_ips = self.df.nlargest(top_n, 'threat_score')[
            ['ip_address', 'threat_score', 'source', 'country_code']
        ]
        return top_ips.to_dict('records')

    def get_daily_threat_trends(self, days=7):
        if self.df.empty:
            return {}
        self.df['date'] = pd.to_datetime(self.df['extracted_at']).dt.date
        daily_counts = self.df.groupby('date').size().to_dict()
        return daily_counts

    def create_visualizations(self, output_dir='../reports/'):
        if self.df.empty:
            logger.warning("No data available for visualization")
            return

        os.makedirs(output_dir, exist_ok=True)

        plt.style.use('default')
        sns.set_palette("husl")

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        top_ips = self.df.nlargest(10, 'threat_score')
        ax1.barh(range(len(top_ips)), top_ips['threat_score'])
        ax1.set_yticks(range(len(top_ips)))
        ax1.set_yticklabels(top_ips['ip_address'])
        ax1.set_xlabel('Threat Score')
        ax1.set_title('Top 10 Malicious IPs by Threat Score')

        source_counts = self.df['source'].value_counts()
        ax2.pie(source_counts.values, labels=source_counts.index, autopct='%1.1f%%')
        ax2.set_title('Threat Sources Distribution')

        plt.tight_layout()
        plt.savefig(f'{output_dir}/threat_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()

        logger.info(f"Visualizations saved to {output_dir}/threat_analysis.png")

    def generate_report(self):
        if self.df.empty:
            return "No data available for analysis"

        top_ips = self.get_top_malicious_ips()
        daily_trends = self.get_daily_threat_trends()

        report = f"""
# Cyber Threat Intelligence Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total IPs analyzed: {len(self.df)}
- Average threat score: {self.df['threat_score'].mean():.2f}
- Data sources: {', '.join(self.df['source'].unique())}

## Top 5 Most Malicious IPs
"""
        for i, ip_data in enumerate(top_ips, 1):
            report += f"{i}. {ip_data['ip_address']} (Score: {ip_data['threat_score']}, Country: {ip_data['country_code']})\n"

        report += f"""
## Daily Threat Trends (Last 7 Days)
"""
        for date, count in sorted(daily_trends.items()):
            report += f"- {date}: {count} threats\n"

        return report
