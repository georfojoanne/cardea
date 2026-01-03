#!/usr/bin/env python3
"""
KitNET Anomaly Detector
Implementation of KitNET ensemble autoencoder for network anomaly detection
"""

import numpy as np
import pickle
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class Autoencoder:
    """Simple autoencoder implementation for KitNET"""
    
    def __init__(self, input_size: int, hidden_size: int = None):
        self.input_size = input_size
        self.hidden_size = hidden_size or max(input_size // 2, 1)
        
        # Initialize weights
        self.weights_encoder = np.random.normal(
            0, 0.1, (self.input_size, self.hidden_size)
        )
        self.weights_decoder = np.random.normal(
            0, 0.1, (self.hidden_size, self.input_size)
        )
        self.bias_encoder = np.zeros(self.hidden_size)
        self.bias_decoder = np.zeros(self.input_size)
        
        self.learning_rate = 0.01
        
    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Forward pass through autoencoder"""
        # Encoder
        hidden = np.tanh(np.dot(x, self.weights_encoder) + self.bias_encoder)
        # Decoder
        output = np.tanh(np.dot(hidden, self.weights_decoder) + self.bias_decoder)
        return hidden, output
    
    def train_step(self, x: np.ndarray) -> float:
        """Single training step"""
        hidden, output = self.forward(x)
        
        # Calculate loss (MSE)
        loss = np.mean((x - output) ** 2)
        
        # Backpropagation
        output_error = 2 * (output - x) / x.shape[0]
        output_delta = output_error * (1 - output ** 2)  # tanh derivative
        
        hidden_error = np.dot(output_delta, self.weights_decoder.T)
        hidden_delta = hidden_error * (1 - hidden ** 2)  # tanh derivative
        
        # Update weights
        self.weights_decoder -= self.learning_rate * np.dot(hidden.T, output_delta)
        self.bias_decoder -= self.learning_rate * np.sum(output_delta, axis=0)
        self.weights_encoder -= self.learning_rate * np.dot(x.T, hidden_delta)
        self.bias_encoder -= self.learning_rate * np.sum(hidden_delta, axis=0)
        
        return loss
    
    def predict(self, x: np.ndarray) -> float:
        """Predict anomaly score"""
        _, output = self.forward(x)
        return np.mean((x - output) ** 2)

class KitNETDetector:
    """KitNET ensemble autoencoder for network anomaly detection"""
    
    def __init__(self, model_path: Path, threshold: float = 0.95):
        self.model_path = model_path
        self.threshold = threshold
        self.autoencoders: List[Autoencoder] = []
        self.scaler = StandardScaler()
        self.feature_groups: List[List[int]] = []
        self.training_mode = True
        self.training_samples = 0
        self.max_training_samples = 1000  # Training phase length - reduced for faster deployment
        self.anomaly_scores_history = []
        
        logger.info(f"Initializing KitNET with threshold: {threshold}")
    
    async def initialize(self):
        """Initialize or load existing model"""
        if self.model_path.exists():
            logger.info("📁 Loading existing KitNET model...")
            self.load_model()
        else:
            logger.info("🧠 No existing model found, starting training phase...")
            self.training_mode = True
    
    def extract_features(self, packet_data: dict) -> np.ndarray:
        """Extract numerical features from Zeek conn.log packet data"""
        features = []
        
        # Zeek conn.log specific features
        features.extend([
            packet_data.get("orig_bytes", 0),  # Original bytes sent
            packet_data.get("resp_bytes", 0),  # Response bytes
            packet_data.get("duration", 0.0),  # Connection duration
            packet_data.get("src_port", 0),    # id.orig_p
            packet_data.get("dest_port", 0),   # id.resp_p
            self._ip_to_int(packet_data.get("src_ip", "0.0.0.0")),  # id.orig_h
            self._ip_to_int(packet_data.get("dest_ip", "0.0.0.0")), # id.resp_h
            self._protocol_to_int(packet_data.get("protocol", "tcp")),
            packet_data.get("orig_pkts", 0),   # Packets from originator
            packet_data.get("resp_pkts", 0),   # Packets from responder
        ])
        
        # Time-based features from Zeek timestamp
        timestamp = packet_data.get("timestamp", datetime.now().isoformat())
        time_features = self._extract_time_features(timestamp)
        features.extend(time_features)
        
        # Zeek-specific flow features
        flow_features = self._extract_zeek_flow_features(packet_data)
        features.extend(flow_features)
        
        return np.array(features, dtype=np.float32).reshape(1, -1)
    
    def detect_anomaly(self, features: np.ndarray) -> float:
        """Detect anomaly and return anomaly score (0.0 - 1.0)"""
        if self.training_mode:
            return self._train_with_sample(features)
        else:
            return self._predict_anomaly(features)
    
    def _train_with_sample(self, features: np.ndarray) -> float:
        """Train autoencoders with new sample during training phase"""
        self.training_samples += 1
        
        # Initialize autoencoders on first sample
        if not self.autoencoders and features.shape[1] > 0:
            self._initialize_autoencoders(features.shape[1])
            
        if not self.autoencoders:
            return 0.0
            
        # Normalize features
        if self.training_samples == 1:
            self.scaler.partial_fit(features)
            
        features_normalized = self.scaler.transform(features)
        
        # Train each autoencoder
        total_loss = 0.0
        for i, autoencoder in enumerate(self.autoencoders):
            if i < len(self.feature_groups):
                feature_subset = features_normalized[:, self.feature_groups[i]]
                loss = autoencoder.train_step(feature_subset)
                total_loss += loss
        
        # Switch to detection mode after training
        if self.training_samples >= self.max_training_samples:
            self.training_mode = False
            self.save_model()
            logger.info(f"✅ Training complete after {self.training_samples} samples")
        
        # Return normalized training loss as temporary score
        avg_loss = total_loss / len(self.autoencoders) if self.autoencoders else 0.0
        return min(avg_loss / 10.0, 1.0)  # Normalize to 0-1 range
    
    def _predict_anomaly(self, features: np.ndarray) -> float:
        """Predict anomaly score using trained autoencoders"""
        if not self.autoencoders:
            return 0.0
            
        features_normalized = self.scaler.transform(features)
        
        # Get anomaly scores from each autoencoder
        scores = []
        for i, autoencoder in enumerate(self.autoencoders):
            if i < len(self.feature_groups):
                feature_subset = features_normalized[:, self.feature_groups[i]]
                score = autoencoder.predict(feature_subset)
                scores.append(score)
        
        # Ensemble anomaly score (max of individual scores)
        ensemble_score = max(scores) if scores else 0.0
        
        # Normalize to 0-1 range
        normalized_score = min(ensemble_score / 5.0, 1.0)
        
        # Track scores for adaptive threshold
        self.anomaly_scores_history.append(normalized_score)
        if len(self.anomaly_scores_history) > 1000:
            self.anomaly_scores_history = self.anomaly_scores_history[-1000:]
        
        return normalized_score
    
    def _initialize_autoencoders(self, num_features: int):
        """Initialize ensemble of autoencoders"""
        logger.info(f"🔧 Initializing autoencoders for {num_features} features...")
        
        # Create feature groups for ensemble
        self.feature_groups = self._create_feature_groups(num_features)
        
        # Create autoencoder for each feature group
        for i, feature_group in enumerate(self.feature_groups):
            autoencoder = Autoencoder(len(feature_group))
            self.autoencoders.append(autoencoder)
        
        logger.info(f"✅ Created {len(self.autoencoders)} autoencoders")
    
    def _create_feature_groups(self, num_features: int) -> List[List[int]]:
        """Create feature groups for ensemble learning"""
        groups = []
        
        # Create overlapping groups of features
        group_size = max(3, num_features // 3)
        for i in range(0, num_features, group_size // 2):
            group = list(range(i, min(i + group_size, num_features)))
            if len(group) >= 2:  # Ensure minimum group size
                groups.append(group)
        
        # Ensure we have at least one group
        if not groups and num_features > 0:
            groups.append(list(range(num_features)))
            
        return groups
    
    def _ip_to_int(self, ip_str: str) -> int:
        """Convert IP address string to integer"""
        try:
            parts = ip_str.split('.')
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
                   (int(parts[2]) << 8) + int(parts[3])
        except:
            return 0
    
    def _protocol_to_int(self, protocol: str) -> int:
        """Convert protocol string to integer"""
        protocol_map = {"tcp": 6, "udp": 17, "icmp": 1}
        return protocol_map.get(protocol.lower(), 0)
    
    def _extract_time_features(self, timestamp_str: str) -> List[float]:
        """Extract time-based features"""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return [
                dt.hour / 24.0,  # Hour of day (0-1)
                dt.weekday() / 6.0,  # Day of week (0-1)
                dt.second / 59.0,  # Second (0-1)
            ]
        except:
            return [0.0, 0.0, 0.0]
    
    def _extract_zeek_flow_features(self, packet_data: dict) -> List[float]:
        """Extract Zeek conn.log specific flow features"""
        # Connection state mapping
        conn_state_map = {
            "S0": 0.1, "S1": 0.2, "SF": 0.3, "REJ": 0.4, "S2": 0.5,
            "S3": 0.6, "RSTO": 0.7, "RSTR": 0.8, "RSTOS0": 0.9, "RSTRH": 1.0
        }
        
        conn_state = packet_data.get("conn_state", "S0")
        conn_state_score = conn_state_map.get(conn_state, 0.0)
        
        # Service type encoding
        service = packet_data.get("service", "")
        service_score = len(service) / 20.0 if service else 0.0  # Normalize service name length
        
        return [
            conn_state_score,  # Connection state
            service_score,     # Service type indicator
            min(packet_data.get("duration", 0.0) / 3600.0, 1.0),  # Duration normalized to hours
            min((packet_data.get("orig_bytes", 0) + packet_data.get("resp_bytes", 0)) / 1000000.0, 1.0)  # Total bytes normalized to MB
        ]
    
    def save_model(self):
        """Save trained model to disk"""
        model_data = {
            'autoencoders': self.autoencoders,
            'scaler': self.scaler,
            'feature_groups': self.feature_groups,
            'threshold': self.threshold,
            'training_samples': self.training_samples
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
            
        logger.info(f"💾 Model saved to {self.model_path}")
    
    def load_model(self):
        """Load trained model from disk"""
        with open(self.model_path, 'rb') as f:
            model_data = pickle.load(f)
            
        self.autoencoders = model_data['autoencoders']
        self.scaler = model_data['scaler']
        self.feature_groups = model_data['feature_groups']
        self.training_samples = model_data['training_samples']
        self.training_mode = False
        
        logger.info(f"📂 Model loaded from {self.model_path}")