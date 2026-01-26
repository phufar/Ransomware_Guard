import math
from collections import Counter
import os

class EntropyCalculator:
    """Calculate Shanon Entropy for detecting encryption"""
    def __init__(self, threshold=7.5):
        self.threshold=threshold
    
    def calculate_entropy(self, data):
        if not data:
            return 0.0
        
        byte_counts = Counter(data)
        data_len = len(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def calculate_file_entropy(self, file_path, chunk_size=8192):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        
        if file_size == 0:
            return {
                'entropy' : 0.0,
                'file_size': 0,
                'suspicious': False
            }
            
        if file_size < chunk_size * 10:
            with open(file_path, 'rb') as f:
                data = f.read()
            entropy = self.calculate_entropy(data)
        else:
            entropy = self._calculate_large_file_entropy(file_path, chunk_size)
        
        return {
            'entropy' : entropy,
            'file_size': file_size,
            'suspicious': entropy >= self.threshold
        }
            
    def _calculate_large_file_entropy(self, file_path, chunk_size):
        file_size = os.path.getsize(file_path)
        
        positions = [
            0,
            file_size // 2,
            max(0, file_size - chunk_size) 
        ]
        
        all_data = bytearray()
        
        with open(file_path, 'rb') as f:
            for pos in positions:   
                f.seek(pos)
                chunk = f.read(chunk_size)
                all_data.extend(chunk)
                
        return self.calculate_entropy(all_data)
    
    def compare_entropy_change(self, old_file_path, new_file_path):
        old_result = self.calculate_file_entropy(old_file_path)
        new_result = self.calculate_file_entropy(new_file_path)
        
        entropy_change = new_result['entropy'] - old_result['entropy']
        
        suspicious_change = entropy_change > 2.0
        
        return {
            'old_entropy' : old_result['entropy'],
            'new_entropy' : new_result['entropy'],
            'entropy_change' : entropy_change,
            'suspicious': suspicious_change or new_result['suspicious']
        }
        
    def analyze_file(self, file_path): 
        result = self.calculate_file_entropy(file_path)
        entropy = result['entropy']
        
        if entropy < 6.0:
            risk_level = 'low'
        elif entropy < 7.0:
            risk_level = 'medium'
        elif entropy < 7.5:
            risk_level = 'high'
        else:
            risk_level = 'extreme'
            
        result['risk_level'] = risk_level
        
        return result 