"""
BackupManager - Automatic File Backup & Restore for Ransomware Guard

Creates backups ONLY when a file modification is detected (via eBPF or Watchdog).
After entropy analysis:
    - If entropy is normal  -> backup is removed (no threat)
    - If entropy is high    -> process is killed, file is restored from backup

Backup files are stored in a hidden directory alongside the watched files.
Each backup includes a metadata JSON file for integrity verification.
"""

import os
import shutil
import time
import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger("ransomware_guard.backup")

# Backup directory name (hidden, created inside watched directory)
DEFAULT_BACKUP_DIR_NAME = ".ransomware_guard_backups"
MAX_BACKUP_AGE_HOURS = 24


class BackupManager:
    """
    Manages file backups triggered by file modification events.

    Backup lifecycle:
        1. File modification detected -> create_backup(file_path)
        2. Entropy analysis runs on the modified file
        3a. Entropy normal -> remove_backup(file_path)
        3b. Entropy high   -> kill process -> restore_backup(file_path)
    """

    def __init__(self, backup_dir: Optional[str] = None):
        """
        Args:
            backup_dir: Custom backup directory path.
                        If None, creates backup dir next to each file.
        """
        if backup_dir:
            self.backup_dir = Path(backup_dir)
        else:
            self.backup_dir = None

        self._lock = threading.Lock()
        self._active_backups: Dict[str, str] = {}  # {original_path: backup_path}
        self.stats = {
            'backups_created': 0,
            'backups_restored': 0,
            'backups_removed': 0,
        }

    def _ensure_backup_dir(self, file_path: str) -> Path:
        """Create and return the backup directory for a given file."""
        if self.backup_dir:
            backup_dir = self.backup_dir
        else:
            parent = Path(file_path).parent
            backup_dir = parent / DEFAULT_BACKUP_DIR_NAME

        backup_dir.mkdir(parents=True, exist_ok=True)
        return backup_dir

    def _generate_backup_name(self, file_path: str) -> str:
        """Generate a unique backup filename with millisecond timestamp."""
        basename = os.path.basename(file_path)
        timestamp = int(time.time() * 1000)
        return f"{basename}.{timestamp}.RGswap"

    def _compute_hash(self, file_path: str) -> Optional[str]:
        """Compute SHA-256 hash for integrity verification."""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (OSError, IOError):
            return None

    def create_backup(self, file_path: str) -> Optional[str]:
        """
        Create a backup of a file when modification is detected.

        Called by FileMonitor when a write event is captured (via eBPF
        or Watchdog). The backup preserves the file's current state
        before the modification is analyzed.

        Args:
            file_path: Absolute path to the file being modified

        Returns:
            Path to the backup file, or None if backup failed
        """
        abs_path = os.path.abspath(file_path)

        # Skip non-existent or empty files
        if not os.path.exists(abs_path):
            return None
        try:
            file_size = os.path.getsize(abs_path)
            if file_size == 0:
                return None
        except OSError:
            return None

        # Skip our own backup files
        if DEFAULT_BACKUP_DIR_NAME in abs_path:
            return None

        with self._lock:
            try:
                backup_dir = self._ensure_backup_dir(abs_path)
                backup_name = self._generate_backup_name(abs_path)
                backup_path = str(backup_dir / backup_name)

                # Copy file preserving metadata (permissions, timestamps)
                shutil.copy2(abs_path, backup_path)

                # Save metadata for integrity verification
                metadata = {
                    'original_path': abs_path,
                    'backup_path': backup_path,
                    'file_hash': self._compute_hash(abs_path),
                    'file_size': file_size,
                    'timestamp': time.time(),
                }
                with open(backup_path + '.meta.json', 'w') as f:
                    json.dump(metadata, f, indent=2)

                self._active_backups[abs_path] = backup_path
                self.stats['backups_created'] += 1
                logger.debug(f"Backup created: {os.path.basename(abs_path)}")
                return backup_path

            except Exception as e:
                logger.error(f"Backup failed for {abs_path}: {e}")
                return None

    def restore_backup(self, file_path: str) -> bool:
        """
        Restore a file from backup after ransomware is detected and killed.

        Copies the backup back to the original path and verifies
        integrity using the stored SHA-256 hash.

        Args:
            file_path: Original file path to restore

        Returns:
            True if restored and verified successfully
        """
        abs_path = os.path.abspath(file_path)

        with self._lock:
            backup_path = self._active_backups.get(abs_path)
            if not backup_path or not os.path.exists(backup_path):
                logger.warning(f"No backup found for: {abs_path}")
                return False

            try:
                # Restore file from backup
                shutil.copy2(backup_path, abs_path)

                # Verify hash integrity
                meta_path = backup_path + '.meta.json'
                if os.path.exists(meta_path):
                    with open(meta_path, 'r') as f:
                        metadata = json.load(f)
                    original_hash = metadata.get('file_hash')
                    restored_hash = self._compute_hash(abs_path)
                    if (original_hash and restored_hash
                            and original_hash != restored_hash):
                        logger.error(f"Hash mismatch after restore: {abs_path}")
                        return False

                self.stats['backups_restored'] += 1
                logger.info(f"File restored from backup: {abs_path}")

                # Clean up backup files
                self._remove_backup_files(backup_path)
                del self._active_backups[abs_path]
                return True

            except Exception as e:
                logger.error(f"Restore failed for {abs_path}: {e}")
                return False

    def remove_backup(self, file_path: str) -> bool:
        """
        Remove backup when entropy analysis determines the file is safe.

        Called after entropy check shows the modification is benign.

        Args:
            file_path: Original file path whose backup should be removed

        Returns:
            True if backup was removed
        """
        abs_path = os.path.abspath(file_path)

        with self._lock:
            backup_path = self._active_backups.get(abs_path)
            if not backup_path:
                return False

            try:
                self._remove_backup_files(backup_path)
                del self._active_backups[abs_path]
                self.stats['backups_removed'] += 1
                logger.debug(f"Backup removed (safe): {os.path.basename(abs_path)}")
                return True
            except Exception as e:
                logger.error(f"Failed to remove backup for {abs_path}: {e}")
                return False

    def _remove_backup_files(self, backup_path: str):
        """Remove a backup file and its associated metadata file."""
        try:
            if os.path.exists(backup_path):
                os.unlink(backup_path)
            meta_path = backup_path + '.meta.json'
            if os.path.exists(meta_path):
                os.unlink(meta_path)
        except OSError as e:
            logger.error(f"Cleanup error: {e}")

    def cleanup_old_backups(self, max_age_hours: float = MAX_BACKUP_AGE_HOURS):
        """
        Remove stale backup files older than max_age_hours.
        Should be called periodically to prevent disk usage growth.
        """
        if not self.backup_dir or not self.backup_dir.exists():
            return

        cutoff = time.time() - (max_age_hours * 3600)
        removed = 0

        for bak_file in self.backup_dir.glob("*.RGswap"):
            try:
                if bak_file.stat().st_mtime < cutoff:
                    self._remove_backup_files(str(bak_file))
                    removed += 1
            except OSError:
                continue

        if removed:
            logger.info(f"Cleaned up {removed} old backup(s)")

    def has_backup(self, file_path: str) -> bool:
        """Check if an active backup exists for this file."""
        return os.path.abspath(file_path) in self._active_backups

    def get_stats(self) -> Dict:
        """Return backup statistics."""
        return {**self.stats, 'active_backups': len(self._active_backups)}

    def cleanup_all(self):
        """Remove all active backups and the backup directory."""
        with self._lock:
            for backup_path in self._active_backups.values():
                self._remove_backup_files(backup_path)
            self._active_backups.clear()

        if self.backup_dir and self.backup_dir.exists():
            try:
                shutil.rmtree(self.backup_dir)
            except OSError as e:
                logger.error(f"Failed to remove backup dir: {e}")


# --- Self-test ---
if __name__ == "__main__":
    import tempfile
    import secrets

    print("=== BackupManager Test ===\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        bm = BackupManager(backup_dir=os.path.join(tmpdir, "backups"))

        # Create test file
        test_file = os.path.join(tmpdir, "document.txt")
        with open(test_file, 'w') as f:
            f.write("This is the original document content.")
        print(f"Created: {test_file}")

        # Step 1: Backup on modification detected
        backup = bm.create_backup(test_file)
        print(f"Backup:  {backup}")
        assert backup is not None

        # Step 2: Simulate ransomware overwriting
        with open(test_file, 'wb') as f:
            f.write(secrets.token_bytes(1024))
        print("File overwritten with random bytes")

        # Step 3: Restore from backup
        assert bm.restore_backup(test_file)
        with open(test_file, 'r') as f:
            assert f.read() == "This is the original document content."
        print("Restore verified OK")

        # Step 4: Test safe-file removal flow
        safe_file = os.path.join(tmpdir, "safe.txt")
        with open(safe_file, 'w') as f:
            f.write("Safe content")
        bm.create_backup(safe_file)
        assert bm.remove_backup(safe_file)
        print("Safe backup removed OK")

        print(f"\nStats: {bm.get_stats()}")
        print("\nAll tests passed!")
