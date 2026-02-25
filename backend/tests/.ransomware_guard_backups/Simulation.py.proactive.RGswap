#!/usr/bin/env python3
"""
Ransomware Guard - Testing & Simulation Module
Simulates ransomware behavior to test the detection system.

WARNING: This creates high-entropy files to trigger detection.
         Only run in monitored test directories!

Usage:
    python3 -m tests.Simulation
    python3 tests/Simulation.py
"""

import os
import sys
import time
import secrets
import tempfile
import shutil
import signal
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.EntropyCalculator import EntropyCalculator
from core.FileMonitor import FileMonitor
from core.ProcessMonitor import ProcessMonitor, ProcessInfo, create_alert_callback
from core.BackupManager import BackupManager


class RansomwareSimulator:
    """Simulates ransomware behavior for testing the detection system."""
    
    def __init__(self, test_dir: str = None):
        """
        Initialize simulator.
        
        Args:
            test_dir: Directory for test files (auto-created if None)
        """
        if test_dir:
            self.test_dir = Path(test_dir)
            self.test_dir.mkdir(parents=True, exist_ok=True)
            self.cleanup_on_exit = False
        else:
            self.test_dir = Path(tempfile.mkdtemp(prefix="ransomware_test_"))
            self.cleanup_on_exit = True
        
        self.created_files = []
        self.results = {
            'normal_files': [],
            'encrypted_files': [],
            'alerts_triggered': []
        }
    
    def create_normal_file(self, filename: str, size_kb: int = 10) -> Path:
        """
        Create a normal text file with low entropy.
        
        Args:
            filename: Name of the file to create
            size_kb: Approximate size in KB
        """
        filepath = self.test_dir / filename
        
        # Repetitive text = low entropy
        content = "This is a normal document. " * (size_kb * 40)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.created_files.append(filepath)
        self.results['normal_files'].append(str(filepath))
        print(f"📄 Created normal file: {filename} ({size_kb}KB)")
        return filepath
    
    def create_encrypted_file(self, filename: str, size_kb: int = 50) -> Path:
        """
        Create a file with random bytes (simulates encrypted/ransomware file).
        High entropy ~7.99
        
        Args:
            filename: Name of the file to create
            size_kb: Size in KB
        """
        filepath = self.test_dir / filename
        
        # Random bytes = maximum entropy
        with open(filepath, 'wb') as f:
            f.write(secrets.token_bytes(size_kb * 1024))
        
        self.created_files.append(filepath)
        self.results['encrypted_files'].append(str(filepath))
        print(f"🔐 Created encrypted file: {filename} ({size_kb}KB)")
        return filepath
    
    def simulate_rapid_encryption(self, count: int = 5, delay: float = 0.5):
        """
        Simulate rapid file encryption attack.
        
        Args:
            count: Number of files to encrypt
            delay: Delay between files (seconds)
        """
        print(f"\n⚡ Simulating rapid encryption attack ({count} files)...")
        
        for i in range(count):
            filename = f"victim_file_{i+1}.encrypted"
            self.create_encrypted_file(filename, size_kb=20)
            time.sleep(delay)
        
        print(f"✅ Rapid encryption simulation complete")
    
    def simulate_mixed_activity(self):
        """Simulate mixed normal and malicious file activity."""
        print("\n🔀 Simulating mixed file activity...")
        
        # Create normal files
        self.create_normal_file("report.txt", size_kb=5)
        time.sleep(0.5)
        
        self.create_normal_file("notes.txt", size_kb=2)
        time.sleep(0.5)
        
        # Suddenly, ransomware attack!
        print("\n⚠️  RANSOMWARE ATTACK BEGINS!")
        self.create_encrypted_file("report.txt.locked", size_kb=5)
        time.sleep(0.3)
        
        self.create_encrypted_file("notes.txt.locked", size_kb=2)
        time.sleep(0.3)
        
        # More encrypted files
        self.create_encrypted_file("backup.zip.encrypted", size_kb=100)
        
        print("✅ Mixed activity simulation complete")
    
    def cleanup(self):
        """Remove all created test files."""
        for filepath in self.created_files:
            try:
                filepath.unlink()
            except:
                pass
        
        if self.cleanup_on_exit and self.test_dir.exists():
            try:
                shutil.rmtree(self.test_dir)
                print(f"🧹 Cleaned up test directory: {self.test_dir}")
            except:
                pass
        
        self.created_files.clear()


class IntegrationTest:
    """Full integration test of the ransomware guard system."""
    
    def __init__(self):
        self.alerts = []
        self.test_dir = None
        self.monitor = None
        self.process_monitor = None
    
    def alert_callback(self, file_path: str, entropy: float):
        """Callback for ransomware detection alerts."""
        self.alerts.append({
            'file': file_path,
            'entropy': entropy,
            'time': time.time()
        })
        print(f"🚨 ALERT: {os.path.basename(file_path)} (entropy: {entropy:.4f})")
    
    def run_entropy_test(self):
        """Test entropy calculation on various file types."""
        print("\n" + "=" * 60)
        print("TEST 1: Entropy Calculator")
        print("=" * 60)
        
        calc = EntropyCalculator(threshold=7.5)
        
        # Create temporary test files
        with tempfile.TemporaryDirectory() as tmpdir:
            # Low entropy file
            low_file = Path(tmpdir) / "low_entropy.txt"
            low_file.write_text("aaaaaaaaaa" * 1000)
            
            # Normal text file
            normal_file = Path(tmpdir) / "normal.txt"
            normal_file.write_text("The quick brown fox jumps over the lazy dog. " * 100)
            
            # High entropy file
            high_file = Path(tmpdir) / "high_entropy.bin"
            high_file.write_bytes(secrets.token_bytes(10000))
            
            tests = [
                ("Low entropy (repetitive)", low_file, False),
                ("Normal text", normal_file, False),
                ("High entropy (random)", high_file, True),
            ]
            
            all_passed = True
            for name, filepath, expected_suspicious in tests:
                result = calc.calculate_file_entropy(str(filepath))
                passed = result['suspicious'] == expected_suspicious
                status = "✅ PASS" if passed else "❌ FAIL"
                
                print(f"  {status} | {name}")
                print(f"         Entropy: {result['entropy']:.4f}, Suspicious: {result['suspicious']}")
                
                if not passed:
                    all_passed = False
        
        return all_passed

    def run_interpreter_trust_test(self):
        """
        TEST: Script interpreters are NOT trusted.

        Verifies that python, node, java are no longer in TRUSTED_APPLICATIONS
        and that is_protected() returns False for interpreter processes.
        """
        print("\n" + "=" * 60)
        print("TEST 2: Interpreter Trust (Flaw #2 Fix)")
        print("=" * 60)

        pm = ProcessMonitor()
        all_passed = True

        # These interpreters must NOT be trusted
        interpreters_to_check = ['python', 'python3', 'node', 'java', 'javac', 'npm']

        for name in interpreters_to_check:
            # Verify not in TRUSTED_APPLICATIONS
            in_trusted = name in pm.TRUSTED_APPLICATIONS
            in_interpreters = name in pm.SCRIPT_INTERPRETERS

            # Create a fake ProcessInfo to test is_protected
            fake_info = ProcessInfo(
                pid=99999, name=name, exe=f"/usr/bin/{name}",
                cmdline=[name, "evil_script.py"], username="testuser",
                create_time=time.time(), cpu_percent=0.0, memory_percent=0.0
            )
            protected = pm.is_protected(fake_info)

            passed = (not in_trusted) and in_interpreters and (not protected)
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"  {status} | '{name}' trusted={in_trusted}, "
                  f"interpreter={in_interpreters}, protected={protected}")

            if not passed:
                all_passed = False

        # Verify compilers ARE still trusted
        for name in ['gcc', 'g++', 'rustc']:
            in_trusted = name in pm.TRUSTED_APPLICATIONS
            passed = in_trusted
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"  {status} | '{name}' still trusted={in_trusted}")
            if not passed:
                all_passed = False

        return all_passed

    def run_proactive_backup_test(self):
        """
        TEST: Proactive backups preserve pre-write content.

        Creates a file, makes a proactive backup, then overwrites with
        random bytes. Verifies that the proactive backup contains the
        ORIGINAL content (not the encrypted version).
        """
        print("\n" + "=" * 60)
        print("TEST 3: Proactive Backup Timing (Flaw #1 Fix)")
        print("=" * 60)

        with tempfile.TemporaryDirectory() as tmpdir:
            bm = BackupManager(backup_dir=os.path.join(tmpdir, "backups"))

            # Step 1: Create original file
            test_file = os.path.join(tmpdir, "document.txt")
            original_content = "This is the original document content."
            with open(test_file, 'w') as f:
                f.write(original_content)

            # Step 2: Create proactive backup (BEFORE any attack)
            proactive = bm.maintain_proactive_backup(test_file)
            assert proactive is not None, "Proactive backup creation failed"
            print(f"  Proactive backup created: {os.path.basename(proactive)}")

            # Step 3: Simulate ransomware overwriting the file
            with open(test_file, 'wb') as f:
                f.write(secrets.token_bytes(1024))
            print("  File overwritten with random bytes (simulated encryption)")

            # Step 4: Get proactive backup and verify it has ORIGINAL content
            backup_path = bm.get_proactive_backup(test_file)
            assert backup_path is not None, "Proactive backup not found"

            with open(backup_path, 'r') as f:
                restored_content = f.read()

            if restored_content == original_content:
                print("  ✅ PASS | Proactive backup contains ORIGINAL content")

                # Step 5: Restore from proactive backup
                shutil.copy2(backup_path, test_file)
                with open(test_file, 'r') as f:
                    final_content = f.read()
                if final_content == original_content:
                    print("  ✅ PASS | File restored successfully from proactive backup")
                    return True
                else:
                    print("  ❌ FAIL | Restored content doesn't match original")
                    return False
            else:
                print("  ❌ FAIL | Proactive backup contains MODIFIED content!")
                return False

    def run_process_timing_test(self):
        """
        TEST: find_recent_writers no longer filters by creation time.

        Verifies that long-running processes are not skipped.
        """
        print("\n" + "=" * 60)
        print("TEST 4: Process Timing Fix (Flaw #4)")
        print("=" * 60)

        import inspect
        pm = ProcessMonitor()

        # Check that the source code does NOT contain 'create_time' filter
        source = inspect.getsource(pm.find_recent_writers)
        has_create_time_filter = 'proc.create_time()' in source or \
                                 'create_time' in source

        if not has_create_time_filter:
            print("  ✅ PASS | find_recent_writers does not filter by create_time")
            return True
        else:
            print("  ❌ FAIL | find_recent_writers still uses create_time filter")
            return False

    def run_sigstop_test(self):
        """
        TEST: SIGSTOP-first strategy exists in FileMonitor.

        Verifies that _freeze_process and _resume_process methods exist
        and that the analysis pipeline uses them.
        """
        print("\n" + "=" * 60)
        print("TEST 5: SIGSTOP-First Strategy (Flaw #5)")
        print("=" * 60)

        import inspect
        all_passed = True

        # Check FileMonitor has freeze/resume methods
        has_freeze = hasattr(FileMonitor, '_freeze_process')
        has_resume = hasattr(FileMonitor, '_resume_process')
        has_frozen_tracking = hasattr(FileMonitor, '_resume_all_frozen')

        status = "✅ PASS" if has_freeze else "❌ FAIL"
        print(f"  {status} | _freeze_process method exists")
        if not has_freeze:
            all_passed = False

        status = "✅ PASS" if has_resume else "❌ FAIL"
        print(f"  {status} | _resume_process method exists")
        if not has_resume:
            all_passed = False

        status = "✅ PASS" if has_frozen_tracking else "❌ FAIL"
        print(f"  {status} | _resume_all_frozen method exists")
        if not has_frozen_tracking:
            all_passed = False

        # Check that _analyze_file uses SIGSTOP (resume on safe, kill on threat)
        source = inspect.getsource(FileMonitor._analyze_file)
        has_resume_call = '_resume_process' in source
        has_sigkill = 'SIGKILL' in source

        status = "✅ PASS" if has_resume_call else "❌ FAIL"
        print(f"  {status} | _analyze_file resumes safe processes")
        if not has_resume_call:
            all_passed = False

        status = "✅ PASS" if has_sigkill else "❌ FAIL"
        print(f"  {status} | _analyze_file can SIGKILL malicious processes")
        if not has_sigkill:
            all_passed = False

        # Check proactive backup is used in restore path
        has_proactive_restore = 'get_proactive_backup' in source
        status = "✅ PASS" if has_proactive_restore else "❌ FAIL"
        print(f"  {status} | _analyze_file restores from proactive backup")
        if not has_proactive_restore:
            all_passed = False

        return all_passed

    def run_ebpf_fullpath_test(self):
        """
        TEST: eBPF event struct includes fullpath field.

        Verifies the EBPFFileEvent dataclass has fullpath and rapid_writes.
        """
        print("\n" + "=" * 60)
        print("TEST 6: eBPF Full Path Resolution (Flaw #3)")
        print("=" * 60)

        from core.EBPFMonitor import EBPFFileEvent
        import dataclasses

        all_passed = True
        fields = {f.name for f in dataclasses.fields(EBPFFileEvent)}

        for field_name in ['fullpath', 'rapid_writes']:
            has_field = field_name in fields
            status = "✅ PASS" if has_field else "❌ FAIL"
            print(f"  {status} | EBPFFileEvent has '{field_name}' field")
            if not has_field:
                all_passed = False

        # Test creating an event with fullpath
        evt = EBPFFileEvent(
            pid=1234, uid=1000, event_type=1, bytes_written=512,
            process_name="test", filename="doc.txt",
            fullpath="/home/user/doc.txt", rapid_writes=True
        )
        has_path = evt.fullpath == "/home/user/doc.txt"
        has_rapid = evt.rapid_writes is True

        status = "✅ PASS" if has_path else "❌ FAIL"
        print(f"  {status} | fullpath correctly stored")
        if not has_path:
            all_passed = False

        status = "✅ PASS" if has_rapid else "❌ FAIL"
        print(f"  {status} | rapid_writes correctly stored")
        if not has_rapid:
            all_passed = False

        return all_passed

    def run_monitor_test(self):
        """Test file monitoring with simulated ransomware."""
        print("\n" + "=" * 60)
        print("TEST 7: File Monitor + Detection (Integration)")
        print("=" * 60)
        
        self.alerts.clear()
        
        # Use a subdirectory in the project instead of /tmp (which is ignored)
        project_root = Path(__file__).parent.parent
        tmpdir = project_root / "tests" / "temp_test_files"
        tmpdir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Setup monitor - CRITICAL: Pass process_monitor for immediate tracking
            self.process_monitor = ProcessMonitor()
            self.monitor = FileMonitor(
                str(tmpdir),
                callback_alert=self.alert_callback,
                process_monitor=self.process_monitor  # Enable process tracking in tests
            )
            
            print(f"  Monitoring: {tmpdir}")
            self.monitor.start()
            time.sleep(0.5)  # Let monitor initialize
            
            # Create test files
            print("  Creating normal file...")
            normal_file = tmpdir / "normal.txt"
            normal_file.write_text("Normal document content " * 500)
            time.sleep(1.5)
            
            print("  Creating high-entropy file (simulated ransomware)...")
            encrypted_file = tmpdir / "encrypted.locked"
            encrypted_file.write_bytes(secrets.token_bytes(50 * 1024))
            time.sleep(2)
            
            self.monitor.stop()
            
            # Check results
            encrypted_detected = any('encrypted.locked' in a['file'] for a in self.alerts)
            normal_not_detected = not any('normal.txt' in a['file'] for a in self.alerts)
            
            if encrypted_detected and normal_not_detected:
                print("  ✅ PASS | High-entropy file detected, normal file ignored")
                return True
            else:
                print("  ❌ FAIL | Detection did not work as expected")
                print(f"         Alerts: {len(self.alerts)}")
                return False
        finally:
            # Cleanup test files
            if tmpdir.exists():
                shutil.rmtree(tmpdir)
    
    def run_all_tests(self):
        """Run all integration tests."""
        print("\n" + "=" * 60)
        print("🛡️  RANSOMWARE GUARD - INTEGRATION TESTS")
        print("   Testing all 5 critical flaw fixes")
        print("=" * 60)
        
        results = {
            'entropy_test': self.run_entropy_test(),
            'interpreter_trust': self.run_interpreter_trust_test(),
            'proactive_backup': self.run_proactive_backup_test(),
            'process_timing': self.run_process_timing_test(),
            'sigstop_strategy': self.run_sigstop_test(),
            'ebpf_fullpath': self.run_ebpf_fullpath_test(),
            'monitor_test': self.run_monitor_test(),
        }
        
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        all_passed = True
        for test_name, passed in results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"  {status} | {test_name}")
            if not passed:
                all_passed = False
        
        print("=" * 60)
        if all_passed:
            print("🎉 ALL TESTS PASSED!")
        else:
            print("⚠️  SOME TESTS FAILED")
        print("=" * 60)
        
        return all_passed


def main():
    """Main entry point for testing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ransomware Guard Testing & Simulation"
    )
    
    parser.add_argument(
        '--test', '-t',
        action='store_true',
        help='Run integration tests'
    )
    
    parser.add_argument(
        '--simulate', '-s',
        choices=['rapid', 'mixed', 'all'],
        help='Run simulation (rapid, mixed, or all)'
    )
    
    parser.add_argument(
        '--dir', '-d',
        type=str,
        default=None,
        help='Directory for simulation files (default: temp directory)'
    )
    
    args = parser.parse_args()
    
    if args.test:
        tester = IntegrationTest()
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
    
    elif args.simulate:
        simulator = RansomwareSimulator(args.dir)
        print(f"\n📁 Test directory: {simulator.test_dir}\n")
        
        try:
            if args.simulate == 'rapid':
                simulator.simulate_rapid_encryption()
            elif args.simulate == 'mixed':
                simulator.simulate_mixed_activity()
            else:  # all
                simulator.simulate_mixed_activity()
                time.sleep(1)
                simulator.simulate_rapid_encryption()
            
            print(f"\n📊 Results:")
            print(f"   Normal files: {len(simulator.results['normal_files'])}")
            print(f"   Encrypted files: {len(simulator.results['encrypted_files'])}")
            
            input("\nPress Enter to cleanup and exit...")
        finally:
            simulator.cleanup()
    
    else:
        # Default: run tests
        parser.print_help()
        print("\n--- Running default integration tests ---\n")
        tester = IntegrationTest()
        tester.run_all_tests()


if __name__ == "__main__":
    main()
