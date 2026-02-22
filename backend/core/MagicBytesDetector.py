"""
MagicBytesDetector - File Type Identification via File Signatures
For Ransomware Guard: Reduces false positives by identifying legitimate
high-entropy files (images, videos, archives, etc.) via their magic bytes.

Key Insight: Encrypted/ransomware files have NO valid magic bytes - they
appear as random garbage from byte 0. Legitimate compressed/media files
always start with a recognized signature.
"""

import os
import logging
from typing import Optional, Dict, Tuple

# Get logger for this module
logger = logging.getLogger("ransomware_guard.magic_bytes")


class MagicBytesDetector:
    """
    Identifies file types by reading the first few bytes (magic bytes/file signature).
    
    This is more reliable than extension checking because:
    1. Ransomware can rename files with fake extensions (.jpg, .pdf)
    2. Extensions can be missing or incorrect
    3. Magic bytes cannot be faked without creating a valid file
    
    Performance: Only reads the first 16 bytes of a file - negligible I/O cost.
    """

    # Maximum bytes to read from file header
    MAX_HEADER_SIZE = 16

    # File signatures database
    # Format: (magic_bytes, offset, file_type, category)
    # Category groups: 'image', 'video', 'audio', 'archive', 'document', 'binary', 'database', 'font'
    SIGNATURES: list[Tuple[bytes, int, str, str]] = [
        # === Images ===
        (b'\xff\xd8\xff',          0, 'jpeg',    'image'),
        (b'\x89PNG\r\n\x1a\n',    0, 'png',     'image'),
        (b'GIF87a',               0, 'gif',     'image'),
        (b'GIF89a',               0, 'gif',     'image'),
        (b'BM',                   0, 'bmp',     'image'),
        (b'RIFF',                 0, 'webp',    'image'),     # WebP (RIFF container)
        (b'\x00\x00\x01\x00',     0, 'ico',     'image'),
        (b'\x49\x49\x2a\x00',     0, 'tiff',    'image'),     # TIFF little-endian
        (b'\x4d\x4d\x00\x2a',     0, 'tiff',    'image'),     # TIFF big-endian
        (b'\x00\x00\x00\x0cjP',   0, 'jpeg2000','image'),     # JPEG 2000

        # === Video ===
        (b'\x1a\x45\xdf\xa3',     0, 'mkv',     'video'),     # Matroska/WebM
        (b'\x00\x00\x00',         0, 'mp4',     'video'),     # MP4/MOV (ftyp at offset 4)
        (b'FLV\x01',              0, 'flv',     'video'),
        (b'\x1a\x45\xdf\xa3',     0, 'webm',    'video'),

        # === Audio ===
        (b'ID3',                  0, 'mp3',     'audio'),     # MP3 with ID3 tag
        (b'\xff\xfb',             0, 'mp3',     'audio'),     # MP3 frame sync
        (b'\xff\xf3',             0, 'mp3',     'audio'),     # MP3 frame sync (MPEG2)
        (b'\xff\xf2',             0, 'mp3',     'audio'),     # MP3 frame sync (MPEG2.5)
        (b'fLaC',                 0, 'flac',    'audio'),
        (b'OggS',                 0, 'ogg',     'audio'),     # Ogg Vorbis/Opus
        (b'RIFF',                 0, 'wav',     'audio'),     # WAV (RIFF container)

        # === Archives (naturally high entropy) ===
        (b'PK\x03\x04',          0, 'zip',     'archive'),   # ZIP, DOCX, XLSX, PPTX, JAR, APK
        (b'PK\x05\x06',          0, 'zip',     'archive'),   # ZIP (empty archive)
        (b'PK\x07\x08',          0, 'zip',     'archive'),   # ZIP (spanned archive)
        (b'\x1f\x8b',            0, 'gzip',    'archive'),   # GZIP, .tar.gz
        (b'BZh',                 0, 'bzip2',   'archive'),
        (b'\xfd7zXZ\x00',        0, 'xz',      'archive'),
        (b'7z\xbc\xaf\x27\x1c',  0, '7z',      'archive'),
        (b'Rar!\x1a\x07\x00',    0, 'rar4',    'archive'),   # RAR v4
        (b'Rar!\x1a\x07\x01\x00',0, 'rar5',    'archive'),   # RAR v5
        (b'\x28\xb5\x2f\xfd',    0, 'zstd',    'archive'),   # Zstandard

        # === Documents ===
        (b'%PDF',                 0, 'pdf',     'document'),
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, 'ole2', 'document'),  # MS Office legacy (.doc, .xls, .ppt)

        # === Binaries / Executables ===
        (b'MZ',                   0, 'exe',     'binary'),    # Windows PE (.exe, .dll)
        (b'\x7fELF',             0, 'elf',     'binary'),    # Linux ELF binary
        (b'\xfe\xed\xfa\xce',    0, 'macho32', 'binary'),    # macOS Mach-O 32-bit
        (b'\xfe\xed\xfa\xcf',    0, 'macho64', 'binary'),    # macOS Mach-O 64-bit
        (b'\xca\xfe\xba\xbe',    0, 'macho_universal', 'binary'),  # macOS Universal binary
        (b'\xce\xfa\xed\xfe',    0, 'macho32_le', 'binary'), # macOS Mach-O 32 LE
        (b'\xcf\xfa\xed\xfe',    0, 'macho64_le', 'binary'), # macOS Mach-O 64 LE

        # === Databases ===
        (b'SQLite format 3\x00', 0, 'sqlite',  'database'),

        # === Fonts ===
        (b'\x00\x01\x00\x00',    0, 'ttf',     'font'),      # TrueType
        (b'OTTO',                 0, 'otf',     'font'),      # OpenType

        # === Disk Images ===
        (b'\x00\x00\x00',        0, 'iso',     'disk_image'),  # Could be ISO or MP4 - handled by length
    ]

    # Categories that are known to have legitimately high entropy
    HIGH_ENTROPY_CATEGORIES = {'image', 'video', 'audio', 'archive', 'document', 'binary', 'font', 'disk_image'}

    def __init__(self):
        """Initialize MagicBytesDetector."""
        # Pre-sort signatures by length (longest first) for accurate matching
        self.signatures = sorted(
            self.SIGNATURES,
            key=lambda s: len(s[0]),
            reverse=True
        )
        logger.debug(f"MagicBytesDetector initialized with {len(self.signatures)} signatures")

    def detect_file_type(self, file_path: str) -> Dict:
        """
        Detect the file type by reading its magic bytes.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            Dictionary with detection results:
            {
                'file_path': str,
                'detected_type': str or None,
                'category': str or None,
                'is_known_type': bool,
                'naturally_high_entropy': bool,
                'status': str,
                'error': str or None
            }
        """
        result = {
            'file_path': file_path,
            'detected_type': None,
            'category': None,
            'is_known_type': False,
            'naturally_high_entropy': False,
            'status': 'ok',
            'error': None
        }

        if not os.path.exists(file_path):
            result['status'] = 'error'
            result['error'] = 'File not found'
            return result

        try:
            file_size = os.path.getsize(file_path)

            # Skip empty files
            if file_size == 0:
                result['status'] = 'skipped'
                return result

            # Read only the first N bytes (very fast)
            with open(file_path, 'rb') as f:
                header = f.read(self.MAX_HEADER_SIZE)

            # Try to match against known signatures
            for magic, offset, file_type, category in self.signatures:
                if len(header) >= offset + len(magic):
                    if header[offset:offset + len(magic)] == magic:
                        # Special case: Distinguish MP4 from other \x00\x00\x00 files
                        if magic == b'\x00\x00\x00' and file_type in ('mp4', 'iso'):
                            if not self._verify_mp4(header):
                                continue

                        # Special case: Distinguish WAV from WebP (both RIFF)
                        if magic == b'RIFF' and len(header) >= 12:
                            riff_type = header[8:12]
                            if riff_type == b'WEBP':
                                file_type = 'webp'
                                category = 'image'
                            elif riff_type == b'WAVE':
                                file_type = 'wav'
                                category = 'audio'
                            elif riff_type == b'AVI ':
                                file_type = 'avi'
                                category = 'video'

                        result['detected_type'] = file_type
                        result['category'] = category
                        result['is_known_type'] = True
                        result['naturally_high_entropy'] = category in self.HIGH_ENTROPY_CATEGORIES

                        logger.debug(f"Detected: {file_path} -> {file_type} ({category})")
                        return result

            # No match found - unknown file type
            logger.debug(f"Unknown file type: {file_path}")
            return result

        except PermissionError:
            result['status'] = 'error'
            result['error'] = 'Permission denied'
            logger.warning(f"Permission denied: {file_path}")
        except OSError as e:
            result['status'] = 'error'
            result['error'] = f'OS Error: {str(e)}'
            logger.error(f"OS Error reading {file_path}: {e}")
        except Exception as e:
            result['status'] = 'error'
            result['error'] = f'Unexpected: {str(e)}'
            logger.error(f"Unexpected error reading {file_path}: {e}")

        return result

    def is_known_safe_type(self, file_path: str) -> bool:
        """
        Quick check: Is this file a known type that naturally has high entropy?
        
        Use this in the detection pipeline to skip false positives:
            if entropy >= threshold and not detector.is_known_safe_type(file_path):
                trigger_alert()
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file is a known type with naturally high entropy
        """
        result = self.detect_file_type(file_path)
        return result['naturally_high_entropy']

    def _verify_mp4(self, header: bytes) -> bool:
        """
        Verify MP4/MOV format by checking for 'ftyp' box.
        MP4 files have 'ftyp' at offset 4 after the box size.
        """
        if len(header) >= 8:
            return header[4:8] == b'ftyp'
        return False

    def get_extension_mismatch(self, file_path: str) -> Optional[Dict]:
        """
        Check if the file extension matches the detected magic bytes.
        A mismatch could indicate:
        1. Ransomware renaming encrypted files with legitimate extensions
        2. Simple miscategorization
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with mismatch info, or None if no mismatch
        """
        result = self.detect_file_type(file_path)

        if not result['is_known_type']:
            return None

        actual_ext = os.path.splitext(file_path)[1].lower()
        detected_type = result['detected_type']

        # Map detected types to expected extensions
        type_to_extensions = {
            'jpeg':    {'.jpg', '.jpeg', '.jpe', '.jfif'},
            'png':     {'.png'},
            'gif':     {'.gif'},
            'bmp':     {'.bmp', '.dib'},
            'webp':    {'.webp'},
            'ico':     {'.ico'},
            'tiff':    {'.tif', '.tiff'},
            'jpeg2000':{'.jp2', '.j2k'},
            'mkv':     {'.mkv'},
            'webm':    {'.webm'},
            'mp4':     {'.mp4', '.m4v', '.m4a', '.mov'},
            'flv':     {'.flv'},
            'avi':     {'.avi'},
            'mp3':     {'.mp3'},
            'flac':    {'.flac'},
            'ogg':     {'.ogg', '.oga', '.ogv', '.opus'},
            'wav':     {'.wav'},
            'zip':     {'.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk', '.odt', '.ods'},
            'gzip':    {'.gz', '.tgz'},
            'bzip2':   {'.bz2'},
            'xz':      {'.xz'},
            '7z':      {'.7z'},
            'rar4':    {'.rar'},
            'rar5':    {'.rar'},
            'zstd':    {'.zst'},
            'pdf':     {'.pdf'},
            'ole2':    {'.doc', '.xls', '.ppt', '.msg'},
            'exe':     {'.exe', '.dll', '.sys', '.scr'},
            'elf':     {'', '.so', '.bin', '.o'},
            'macho32': {'', '.dylib', '.bundle'},
            'macho64': {'', '.dylib', '.bundle'},
            'macho_universal': {'', '.dylib', '.bundle'},
            'macho32_le': {'', '.dylib', '.bundle'},
            'macho64_le': {'', '.dylib', '.bundle'},
            'sqlite':  {'.db', '.sqlite', '.sqlite3'},
            'ttf':     {'.ttf'},
            'otf':     {'.otf'},
        }

        expected_extensions = type_to_extensions.get(detected_type, set())

        if actual_ext and expected_extensions and actual_ext not in expected_extensions:
            mismatch = {
                'file_path': file_path,
                'actual_extension': actual_ext,
                'detected_type': detected_type,
                'expected_extensions': list(expected_extensions),
                'suspicious': True
            }
            logger.warning(
                f"Extension mismatch: {file_path} has extension '{actual_ext}' "
                f"but magic bytes say '{detected_type}' (expected: {expected_extensions})"
            )
            return mismatch

        return None


# --- Test Execution ---
if __name__ == "__main__":
    import sys

    print("=== MagicBytesDetector Test ===\n")

    detector = MagicBytesDetector()

    # If a file path is provided as argument, check it
    if len(sys.argv) > 1:
        for path in sys.argv[1:]:
            result = detector.detect_file_type(path)
            print(f"File: {path}")
            print(f"  Type: {result['detected_type'] or 'UNKNOWN'}")
            print(f"  Category: {result['category'] or 'N/A'}")
            print(f"  Known type: {result['is_known_type']}")
            print(f"  Naturally high entropy: {result['naturally_high_entropy']}")

            mismatch = detector.get_extension_mismatch(path)
            if mismatch:
                print(f"  ⚠️  EXTENSION MISMATCH: ext='{mismatch['actual_extension']}' "
                      f"but detected as '{mismatch['detected_type']}'")
            print()
    else:
        print(f"Loaded {len(detector.signatures)} file signatures")
        print(f"\nUsage: python MagicBytesDetector.py <file1> [file2] ...")
        print(f"\nExample:")
        print(f"  python MagicBytesDetector.py photo.jpg document.pdf archive.zip")

    print("\n MagicBytesDetector ready!")
