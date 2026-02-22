import math
import os
import logging
from collections import Counter

# Get logger for this module
logger = logging.getLogger("ransomware_guard.entropy")

class EntropyCalculator:
    """
    Robust Shannon Entropy Calculator for Ransomware Detection.
    Focused on Performance and Crash Prevention.
    """
    def __init__(self, threshold=7.5):
        self.threshold = threshold
        # Pre-calculation of log tables could be a micro-optimization, 
        # but standard math.log2 is fast enough for 256 iterations.

    def calculate_entropy(self, data):
        """Calculates Shannon Entropy from byte data (Returns 0.0 - 8.0)."""
        if not data:
            return 0.0
        
        # Counter is extremely fast in Python (C-optimized)
        byte_counts = Counter(data)
        data_len = len(data)
        
        entropy = 0.0
        # This loop runs at most 256 times (byte values 0-255), 
        # making it very fast and CPU efficient.
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def calculate_file_entropy(self, file_path, chunk_size=8192):
        """
        Analyzes file safely (Crash-proof).
        Always returns a Dictionary, never raises an Exception.
        """
        result = {
            'file_path': file_path,
            'entropy': 0.0,
            'file_size': 0,
            'suspicious': False,
            'status': 'ok',
            'error': None
        }

        if not os.path.exists(file_path):
            result['status'] = 'error'
            result['error'] = 'File not found'
            logger.debug(f"File not found: {file_path}")
            return result

        try:
            file_size = os.path.getsize(file_path)
            result['file_size'] = file_size

            # Case 1: Empty file
            if file_size == 0:
                result['status'] = 'skipped'
                return result
            
            # Case 2: Small file 
            # Read entirely into memory to save IO ops. 
            # Cutoff at 10 chunks (approx 80KB).
            if file_size < chunk_size * 10:
                with open(file_path, 'rb') as f:
                    data = f.read() # Read all
                entropy = self.calculate_entropy(data)
            
            # Case 3: Large file 
            # Use sampling technique (Head/Mid/Tail) for performance.
            else:
                entropy = self._calculate_large_file_entropy(file_path, file_size, chunk_size)

            result['entropy'] = entropy
            result['suspicious'] = entropy >= self.threshold
            result['risk_level'] = self._get_risk_level(entropy)
            
            if result['suspicious']:
                logger.warning(f"High entropy detected: {file_path} (entropy: {entropy:.4f})")
            else:
                logger.debug(f"File analyzed: {file_path} (entropy: {entropy:.4f})")

        except PermissionError:
            result['status'] = 'error'
            result['error'] = 'Permission denied'
            logger.warning(f"Permission denied: {file_path}")
        except OSError as e:
            result['status'] = 'error'
            result['error'] = f'OS Error: {str(e)}'
            logger.error(f"OS Error analyzing {file_path}: {e}")
        except Exception as e:
            result['status'] = 'error'
            result['error'] = f'Unexpected: {str(e)}'
            logger.error(f"Unexpected error analyzing {file_path}: {e}")

        return result
            
    def _calculate_large_file_entropy(self, file_path, file_size, chunk_size):
        """
        Sampling technique: Reads Head, Middle, and Tail chunks to save I/O.
        Provides excellent performance even for GB-sized files.
        """
        # Calculate read positions
        head_pos = 0
        mid_pos = max(0, (file_size // 2) - (chunk_size // 2))
        tail_pos = max(0, file_size - chunk_size)
        
        positions = sorted(list(set([head_pos, mid_pos, tail_pos])))
        
        all_data = bytearray()
        
        with open(file_path, 'rb') as f:
            for pos in positions:   
                f.seek(pos)
                chunk = f.read(chunk_size)
                all_data.extend(chunk)
                
        return self.calculate_entropy(all_data)
    
    def _get_risk_level(self, entropy):
        """Helper function to determine risk level based on entropy score."""
        if entropy < 6.0: return 'low'
        elif entropy < 7.0: return 'medium'
        elif entropy < 7.5: return 'high'
        else: return 'extreme'

    def compare_entropy_change(self, old_file_path, new_file_path):
        """
        (Optional) Compares entropy between two files.
        Useful for checking files before and after backup/modification.
        """
        old_res = self.calculate_file_entropy(old_file_path)
        new_res = self.calculate_file_entropy(new_file_path)
        
        if old_res['status'] != 'ok' or new_res['status'] != 'ok':
            return {'status': 'error', 'suspicious': False}

        change = new_res['entropy'] - old_res['entropy']
        
        return {
            'status': 'ok',
            'old_entropy': old_res['entropy'],
            'new_entropy': new_res['entropy'],
            'change': change,
            'suspicious': change > 2.0 or new_res['suspicious']
        }