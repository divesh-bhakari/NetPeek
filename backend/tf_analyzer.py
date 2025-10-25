"""
TensorFlow-based Network Traffic Analyzer for NetPeek
No API keys needed - runs completely locally
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
import os
from db_config import get_db_connection

class NetPeekTFAnalyzer:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model = None
        self.model_trained = False
        
    def extract_features(self, file_id):
        """
        Extract features from database for TensorFlow analysis
        """
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                length,
                ttl,
                src_port,
                dst_port,
                protocol,
                HOUR(timestamp) as hour,
                MINUTE(timestamp) as minute,
                SECOND(timestamp) as second
            FROM packets 
            WHERE file_id=%s 
            AND length IS NOT NULL 
            AND length > 0
            LIMIT 10000
        """, (file_id,))
        
        data = cursor.fetchall()
        cursor.close()
        connection.close()
        
        if not data:
            return None
        
        df = pd.DataFrame(data)
        
        # Handle missing values
        df = df.fillna({
            'length': df['length'].mean() if 'length' in df else 0,
            'ttl': 64,
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'Unknown',
            'hour': 0,
            'minute': 0,
            'second': 0
        })
        
        return df
    
    def build_simple_classifier(self, input_dim=7):
        """
        Build a simple neural network for traffic classification
        """
        model = keras.Sequential([
            keras.layers.Dense(64, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dense(3, activation='softmax')  # 3 classes: Normal, Suspicious, Anomalous
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def analyze_traffic_patterns(self, file_id):
        """
        Analyze traffic without training (rule-based + statistical analysis)
        Perfect for real-time insights without pre-training
        """
        df = self.extract_features(file_id)
        
        if df is None or df.empty:
            return {
                'insights': ['No data available for analysis'],
                'statistics': {},
                'risk_level': 'Unknown'
            }
        
        insights = []
        statistics = {}
        
        # 1. Protocol Distribution Analysis
        protocol_counts = df['protocol'].value_counts()
        statistics['protocols'] = protocol_counts.to_dict()
        
        if 'TCP' in protocol_counts and protocol_counts['TCP'] > len(df) * 0.7:
            insights.append(f"High TCP traffic detected ({protocol_counts['TCP']} packets, {protocol_counts['TCP']/len(df)*100:.1f}%) - Normal for web browsing")
        
        if 'ICMP' in protocol_counts and protocol_counts['ICMP'] > 100:
            insights.append(f"⚠️ Elevated ICMP traffic ({protocol_counts['ICMP']} packets) - Possible network scanning or ping flood")
        
        # 2. Packet Size Analysis
        avg_length = df['length'].mean()
        std_length = df['length'].std()
        statistics['avg_packet_size'] = round(avg_length, 2)
        statistics['std_packet_size'] = round(std_length, 2)
        
        if avg_length < 100:
            insights.append(f"Small average packet size ({avg_length:.1f} bytes) - Likely control/acknowledgment packets")
        elif avg_length > 1200:
            insights.append(f"Large average packet size ({avg_length:.1f} bytes) - Data transfer or media streaming detected")
        
        # 3. Port Analysis
        common_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 
                       80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 
                       3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'}
        
        dst_port_counts = df['dst_port'].value_counts().head(5)
        statistics['top_ports'] = dst_port_counts.to_dict()
        
        suspicious_ports = [23, 3389, 21]  # Telnet, RDP, FTP
        for port in suspicious_ports:
            if port in dst_port_counts and dst_port_counts[port] > 10:
                port_name = common_ports.get(port, str(port))
                insights.append(f"⚠️ Detected {dst_port_counts[port]} connections to {port_name} (port {port}) - Unencrypted protocol, security risk")
        
        if 443 in dst_port_counts and dst_port_counts[443] > len(df) * 0.3:
            insights.append(f"✅ Secure HTTPS traffic dominates (port 443) - Good security posture")
        
        # 4. TTL Analysis
        avg_ttl = df['ttl'].mean()
        unique_ttls = df['ttl'].nunique()
        statistics['avg_ttl'] = round(avg_ttl, 2)
        statistics['unique_ttls'] = unique_ttls
        
        if unique_ttls > 20:
            insights.append(f"High TTL diversity ({unique_ttls} unique values) - Traffic from multiple network hops or sources")
        
        if avg_ttl < 32:
            insights.append(f"⚠️ Low average TTL ({avg_ttl:.1f}) - Possible spoofed packets or local network issues")
        
        # 5. Time-based Analysis
        hour_counts = df['hour'].value_counts()
        peak_hour = hour_counts.idxmax()
        statistics['peak_hour'] = int(peak_hour)
        
        if peak_hour >= 0 and peak_hour <= 5:
            insights.append(f"⚠️ Peak activity at {peak_hour}:00 (late night/early morning) - Unusual timing, possible automated scripts")
        else:
            insights.append(f"Peak activity at {peak_hour}:00 - Normal business hours traffic pattern")
        
        # 6. Port Scanning Detection
        unique_dst_ports = df['dst_port'].nunique()
        if unique_dst_ports > 100:
            insights.append(f"🚨 Port scanning detected! {unique_dst_ports} unique destination ports accessed - Possible reconnaissance activity")
        
        # 7. Risk Level Assessment
        risk_score = 0
        if 'ICMP' in protocol_counts and protocol_counts['ICMP'] > 100:
            risk_score += 2
        if unique_dst_ports > 100:
            risk_score += 3
        if 23 in dst_port_counts or 3389 in dst_port_counts:
            risk_score += 2
        if avg_ttl < 32:
            risk_score += 1
        if peak_hour >= 0 and peak_hour <= 5:
            risk_score += 1
        
        if risk_score >= 5:
            risk_level = "🔴 HIGH RISK"
        elif risk_score >= 3:
            risk_level = "🟡 MEDIUM RISK"
        else:
            risk_level = "🟢 LOW RISK"
        
        statistics['risk_score'] = risk_score
        
        return {
            'insights': insights if insights else ['Traffic appears normal - no significant anomalies detected'],
            'statistics': statistics,
            'risk_level': risk_level
        }

# Global analyzer instance
tf_analyzer = NetPeekTFAnalyzer()
