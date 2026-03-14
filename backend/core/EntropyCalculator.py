import math
import os
import base64
import logging
from collections import Counter

# Get logger for this module
logger = logging.getLogger("ransomware_guard.entropy")

# --- Precomputed lookup tables (built once at module load, used by all instances) ---

# Log2 lookup table: _LOG2[n] = log2(n) for n in 1..65535
# Avoids calling math.log2() per byte-value in the entropy loop.
# 65535 covers any realistic byte count within a single file chunk.
_LOG2_TABLE_SIZE = 65536
_LOG2 = [0.0] * _LOG2_TABLE_SIZE
for _i in range(1, _LOG2_TABLE_SIZE):
    _LOG2[_i] = math.log2(_i)

# Base64 valid byte set as a bytes object for C-level translate() operations.
# Contains: A-Za-z0-9+/= plus whitespace (\\n \\r space tab)
_BASE64_KEEP = bytes(
    list(range(0x41, 0x5B)) +  # A-Z
    list(range(0x61, 0x7B)) +  # a-z
    list(range(0x30, 0x3A)) +  # 0-9
    [0x2B, 0x2F, 0x3D,        # + / =
     0x0A, 0x0D, 0x20, 0x09]  # \n \r space tab
)

# Whitespace byte removal table for bytes.translate()
# translate(table, delete) — table=None means no mapping, delete removes those bytes
_WHITESPACE_BYTES = b'\n\r \t'

# Printable ASCII range as bytes for C-level translate
_PRINTABLE_BYTES = bytes(
    list(range(0x20, 0x7F)) +  # space through ~
    [0x0A, 0x0D, 0x09]        # \n \r tab
)


class EntropyCalculator:
    """
    Robust Shannon Entropy Calculator for Ransomware Detection.
    Focused on Performance and Crash Prevention.

    Performance optimizations:
        - Precomputed log2 lookup table (avoids math.log2 per iteration)
        - C-level bytes.translate() for base64 detection (no Python byte loops)
        - Single-pass whitespace stripping via translate table
        - Head/Mid/Tail sampling for files > 80KB
    """
    # Minimum data size to consider for base64 detection
    _BASE64_MIN_SIZE = 64
    # Minimum ratio of valid base64 chars required to flag as base64
    _BASE64_CHAR_RATIO = 0.90

    def __init__(self, threshold=7.5):
        self.threshold = threshold

    def calculate_entropy(self, data):
        """
        Calculates Shannon Entropy from byte data (Returns 0.0 - 8.0).

        Uses a precomputed log2 lookup table to avoid per-iteration
        math.log2() calls. The Counter is C-optimized, and the final
        loop runs at most 256 times (one per unique byte value).
        """
        if not data:
            return 0.0

        byte_counts = Counter(data)
        data_len = len(data)
        log2_len = _LOG2[data_len] if data_len < _LOG2_TABLE_SIZE else math.log2(data_len)

        # Shannon entropy: H = log2(N) - (1/N) * Σ count * log2(count)
        # This avoids computing probability = count/N and then log2(probability)
        # for each value. Instead: H = log2(N) - (1/N) * Σ c*log2(c)
        weighted_sum = 0.0
        for count in byte_counts.values():
            if count < _LOG2_TABLE_SIZE:
                weighted_sum += count * _LOG2[count]
            else:
                weighted_sum += count * math.log2(count)

        return log2_len - weighted_sum / data_len

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

            # Case 2: Small file (< ~80KB)
            # Read entirely into memory to save IO ops.
            if file_size < chunk_size * 10:
                with open(file_path, 'rb') as f:
                    data = f.read()

                # Base64 detection: decode in-memory before entropy calc
                decoded = self._try_decode_base64(data)
                if decoded is not None:
                    result['base64_encoded'] = True
                    logger.info(f"Base64 detected: {file_path} "
                                f"({len(data)}B encoded -> {len(decoded)}B decoded)")
                    entropy = self.calculate_entropy(decoded)
                else:
                    result['base64_encoded'] = False
                    entropy = self.calculate_entropy(data)

            # Case 3: Large file
            # Use sampling technique (Head/Mid/Tail) for performance.
            else:
                entropy, is_b64 = self._calculate_large_file_entropy(
                    file_path, file_size, chunk_size
                )
                result['base64_encoded'] = is_b64

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

        Returns:
            Tuple of (entropy, is_base64_encoded)
        """
        head_pos = 0
        mid_pos = max(0, (file_size // 2) - (chunk_size // 2))
        tail_pos = max(0, file_size - chunk_size)

        positions = sorted(set((head_pos, mid_pos, tail_pos)))

        all_data = bytearray()

        with open(file_path, 'rb') as f:
            for pos in positions:
                f.seek(pos)
                all_data.extend(f.read(chunk_size))

        # Base64 detection on sampled data
        decoded = self._try_decode_base64(bytes(all_data))
        if decoded is not None:
            logger.info(f"Base64 detected (sampled): {file_path}")
            return self.calculate_entropy(decoded), True

        return self.calculate_entropy(all_data), False

    @staticmethod
    def _is_base64_encoded(data: bytes) -> bool:
        """
        Fast heuristic: does this data look like base64 encoding?

        Uses C-level bytes.translate(None, delete=...) to strip all valid
        base64 characters, then checks how many remain. This runs entirely
        in C — no Python-level byte iteration.

        Criteria:
            - At least 64 bytes (avoid false matches on short text)
            - >= 90% of bytes are valid base64 characters
        """
        data_len = len(data)
        if data_len < 64:
            return False

        # Remove all valid base64 bytes — whatever remains is "invalid"
        # This runs in C via bytes.translate(), extremely fast
        invalid = data.translate(None, delete=_BASE64_KEEP)
        valid_count = data_len - len(invalid)

        return (valid_count / data_len) >= 0.90

    @staticmethod
    def _try_decode_base64(data: bytes):
        """
        Attempt to detect and decode base64 data in-memory.

        Base64-encoded ransomware output uses only 64 ASCII characters,
        which drops entropy from ~7.99 to ~6.0 — evading the threshold.
        Decoding in-memory reveals the true entropy of the underlying
        encrypted content.

        Performance:
            - C-level bytes.translate() for both heuristic check and
              whitespace stripping (no Python byte loops)

        Returns:
            Decoded bytes if data is base64-encoded, None otherwise.
            Never writes to disk — decode is purely in-memory.
        """
        if not EntropyCalculator._is_base64_encoded(data):
            return None

        try:
            # Strip whitespace in a single C-level pass
            stripped = data.translate(None, delete=_WHITESPACE_BYTES)

            # Attempt strict decode (validate=True rejects invalid chars)
            decoded = base64.b64decode(stripped, validate=True)

            # Sanity check: decoded should be ~75% of encoded size
            # (base64 expands by 33%)
            decoded_len = len(decoded)
            stripped_len = len(stripped)
            if decoded_len < stripped_len * 0.5 or decoded_len > stripped_len:
                return None

            # Avoid flagging plain ASCII text that happens to be valid base64.
            # Use C-level translate to count non-printable bytes in decoded data.
            sample = decoded[:1024]
            sample_len = len(sample)
            if sample_len > 0:
                non_printable = sample.translate(None, delete=_PRINTABLE_BYTES)
                if (len(non_printable) / sample_len) < 0.15:
                    # > 85% printable → probably normal text, not encrypted
                    return None

            return decoded

        except Exception:
            return None

    @staticmethod
    def _get_risk_level(entropy):
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