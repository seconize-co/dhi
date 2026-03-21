#!/usr/bin/env python3
"""
Dhi - Runtime Intelligence & Protection System
धी (Sanskrit: Intellect / Perception)

Monitors and protects against:
- Data exfiltration by processes
- Unauthorized file modifications
- Suspicious network activity

"Where Ancient Wisdom Meets Modern Security"
"""

import ctypes
import json
import struct
import sys
import time
import argparse
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from enum import Enum

try:
    from bcc import BPF, RINGBUF_OUTPUT, utils
except ImportError:
    print("Error: BCC is not installed. Install with: pip install bcc")
    sys.exit(1)


class EventType(Enum):
    """Event classification"""
    FILE_OPEN = 1
    FILE_WRITE = 2
    FILE_DELETE = 3
    FILE_RENAME = 4
    FILE_CHMOD = 5
    NETWORK_SEND = 6
    SUSPICIOUS = 100


class ProtectionLevel(Enum):
    """Protection enforcement levels"""
    LOG_ONLY = 0
    ALERT = 1
    BLOCK = 2


class ProcessContext:
    """Track per-process statistics"""
    def __init__(self, pid: int, uid: int, comm: str):
        self.pid = pid
        self.uid = uid
        self.comm = comm
        self.created_at = time.time()
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.file_operations = defaultdict(int)
        self.network_destinations = set()
        self.suspicious_flags = 0
        self.events = []
        self.risk_score = 0

    def add_network_activity(self, daddr: str, dport: int, bytes_sent: int):
        """Track network activity"""
        self.total_bytes_sent += bytes_sent
        self.network_destinations.add((daddr, dport))
        
    def add_file_operation(self, path: str, op_type: str):
        """Track file operations"""
        self.file_operations[op_type] += 1
        
    def calculate_risk(self) -> int:
        """Simple risk scoring"""
        risk = 0
        if self.total_bytes_sent > 10 * 1024 * 1024:  # 10MB exfiltration
            risk += 50
        if len(self.network_destinations) > 5:
            risk += 30
        if self.file_operations.get('delete', 0) > 10:
            risk += 40
        if self.file_operations.get('chmod', 0) > 5:
            risk += 20
        return min(risk, 100)


class DhiProtector:
    """Main Dhi runtime protection system"""
    
    def __init__(self, bpf_code: str, protection_level: ProtectionLevel = ProtectionLevel.LOG_ONLY):
        self.bpf_code = bpf_code
        self.protection_level = protection_level
        self.processes: Dict[int, ProcessContext] = {}
        self.blocked_pids = set()
        self.whitelisted_ips = set()
        self.whitelisted_files = set()
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Load BPF program
        self.bpf = None
        self.load_bpf()
        
    def _setup_logger(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger('Dhi')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
        
    def load_bpf(self):
        """Load and compile BPF program"""
        try:
            self.bpf = BPF(text=self.bpf_code)
            self.logger.info("BPF program loaded successfully")
            
            # Attach probes
            self._attach_probes()
            
        except Exception as e:
            self.logger.error(f"Failed to load BPF: {e}")
            sys.exit(1)
            
    def _attach_probes(self):
        """Attach BPF probes to kernel tracepoints"""
        try:
            # File operation probes
            self.bpf.attach_tracepoint("syscalls:sys_enter_openat", "trace_openat")
            self.bpf.attach_tracepoint("syscalls:sys_enter_write", "trace_write")
            self.bpf.attach_tracepoint("syscalls:sys_enter_sendto", "trace_sendto")
            self.bpf.attach_tracepoint("syscalls:sys_enter_unlinkat", "trace_unlinkat")
            self.bpf.attach_tracepoint("syscalls:sys_enter_renameat2", "trace_renameat2")
            self.bpf.attach_tracepoint("syscalls:sys_enter_fchmodat", "trace_fchmodat")
            
            self.logger.info("Probes attached successfully")
        except Exception as e:
            self.logger.warning(f"Some probes may not be available: {e}")
    
    def add_whitelist_ip(self, ip: str):
        """Add IP to network whitelist"""
        self.whitelisted_ips.add(ip)
        self.logger.info(f"Whitelisted IP: {ip}")
        
    def add_whitelist_file(self, path: str):
        """Add file path to whitelist"""
        self.whitelisted_files.add(path)
        self.logger.info(f"Whitelisted file: {path}")
        
    def start_monitoring(self, callback=None):
        """Start monitoring events from BPF ringbuffer"""
        try:
            ringbuf = self.bpf["events"]
            ringbuf.open_ring_buffer(self._event_callback if not callback else callback)
            
            self.logger.info("Monitoring started")
            while True:
                ringbuf.poll()
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            self.logger.info("\nMonitoring stopped")
        except Exception as e:
            self.logger.error(f"Error during monitoring: {e}")
            
    def _event_callback(self, cpu, data, size):
        """Process events from BPF"""
        event = self.bpf["events"].event(data)
        
        pid = event.pid
        uid = event.uid
        
        # Initialize or retrieve process context
        if pid not in self.processes:
            comm = event.comm.decode('utf-8', errors='ignore').strip('\x00')
            self.processes[pid] = ProcessContext(pid, uid, comm)
            
        context = self.processes[pid]
        
        # Determine event type and take action
        self._handle_event(event, context)
        
    def _handle_event(self, event, context: ProcessContext):
        """Handle individual events"""
        event_type = EventType.FILE_OPEN
        
        # Parse event based on type
        if hasattr(event, 'flags'):
            flags = event.flags
            if flags == 0:
                event_type = EventType.FILE_DELETE
            elif flags == 1:
                event_type = EventType.FILE_RENAME
            elif flags == 2:
                event_type = EventType.FILE_CHMOD
                
        if hasattr(event, 'daddr') and event.daddr != 0:
            event_type = EventType.NETWORK_SEND
            self._handle_network_event(event, context, event_type)
        else:
            self._handle_file_event(event, context, event_type)
            
    def _handle_file_event(self, event, context: ProcessContext, event_type: EventType):
        """Handle file operation events"""
        filename = event.filename.decode('utf-8', errors='ignore').strip('\x00')
        
        # Check if whitelisted
        if filename in self.whitelisted_files:
            return
            
        # Detect suspicious patterns
        suspicious = False
        risk_increase = 0
        
        if event_type == EventType.FILE_DELETE:
            context.add_file_operation(filename, 'delete')
            if self._is_suspicious_deletion(filename):
                suspicious = True
                risk_increase = 15
                
        elif event_type == EventType.FILE_CHMOD:
            context.add_file_operation(filename, 'chmod')
            if self._is_suspicious_chmod(event.mode):
                suspicious = True
                risk_increase = 10
                
        elif event_type == EventType.FILE_RENAME:
            context.add_file_operation(filename, 'rename')
            suspicious = self._is_suspicious_rename(filename)
            risk_increase = 5 if suspicious else 0
            
        # Log and potentially block
        log_msg = (f"FILE {event_type.name}: PID={context.pid} ({context.comm}) "
                  f"UID={context.uid} FILE={filename}")
        
        if suspicious:
            context.risk_score += risk_increase
            self.logger.warning(f"[SUSPICIOUS] {log_msg}")
            context.suspicious_flags += 1
            
            if self.protection_level == ProtectionLevel.BLOCK:
                self._block_process(context)
        else:
            self.logger.debug(log_msg)
            
    def _handle_network_event(self, event, context: ProcessContext, event_type: EventType):
        """Handle network activity events"""
        # Convert IP address
        daddr_int = event.daddr
        daddr_str = f"{daddr_int & 0xFF}.{(daddr_int >> 8) & 0xFF}.{(daddr_int >> 16) & 0xFF}.{(daddr_int >> 24) & 0xFF}"
        dport = event.dport
        bytes_sent = event.bytes_sent
        
        context.add_network_activity(daddr_str, dport, bytes_sent)
        
        # Check if whitelisted
        if daddr_str in self.whitelisted_ips:
            return
            
        # Detect suspicious patterns
        suspicious = False
        risk_increase = 0
        
        if self._is_suspicious_port(dport):
            suspicious = True
            risk_increase = 20
            
        if bytes_sent > 1024 * 1024:  # 1MB in single send
            suspicious = True
            risk_increase += 15
            
        log_msg = (f"NETWORK: PID={context.pid} ({context.comm}) "
                  f"DEST={daddr_str}:{dport} BYTES={bytes_sent}")
        
        if suspicious:
            context.risk_score += risk_increase
            self.logger.warning(f"[EXFILTRATION RISK] {log_msg}")
            context.suspicious_flags += 1
            
            if self.protection_level == ProtectionLevel.BLOCK and context.suspicious_flags > 3:
                self._block_process(context)
        else:
            self.logger.info(log_msg)
            
    def _is_suspicious_deletion(self, filename: str) -> bool:
        """Check if file deletion is suspicious"""
        sensitive_patterns = ['/etc/', '/.ssh/', '/home/', '/root/', '.bashrc', '.bash_history']
        return any(pattern in filename for pattern in sensitive_patterns)
        
    def _is_suspicious_chmod(self, mode: int) -> bool:
        """Check if chmod is suspicious (e.g., 777)"""
        return mode == 0o777
        
    def _is_suspicious_rename(self, filename: str) -> bool:
        """Check if rename is suspicious"""
        # Renaming to hidden files or system files
        basename = filename.split('/')[-1]
        return basename.startswith('.') or filename.endswith('.sh')
        
    def _is_suspicious_port(self, port: int) -> bool:
        """Identify suspicious destination ports"""
        # Commonly used for C2, data exfiltration
        suspicious_ports = {
        5555,     # ADB
        6666, 6667, 6668, 6669,  # IRC
        8888, 9999,  # Common proxy/backdoor
        4444, 5555,  # Common remote shells
        }
        return port in suspicious_ports
        
    def _block_process(self, context: ProcessContext):
        """Block a suspicious process"""
        if context.pid not in self.blocked_pids:
            self.logger.critical(f"BLOCKING PID {context.pid} ({context.comm}) - Risk: {context.risk_score}%")
            self.blocked_pids.add(context.pid)
            # In production, would use eBPF return codes or cgroup/seccomp
            # For demo, just log and alert
            
    def get_process_stats(self, pid: int) -> Optional[Dict]:
        """Get statistics for a specific process"""
        if pid not in self.processes:
            return None
            
        ctx = self.processes[pid]
        return {
            'pid': ctx.pid,
            'comm': ctx.comm,
            'uid': ctx.uid,
            'bytes_sent': ctx.total_bytes_sent,
            'bytes_received': ctx.total_bytes_received,
            'file_operations': dict(ctx.file_operations),
            'network_destinations': list(ctx.network_destinations),
            'risk_score': ctx.risk_score,
            'suspicious_flags': ctx.suspicious_flags,
            'uptime': time.time() - ctx.created_at
        }
        
    def get_high_risk_processes(self, threshold: int = 50) -> List[Dict]:
        """Get processes above risk threshold"""
        return [
            self.get_process_stats(pid)
            for pid, ctx in self.processes.items()
            if ctx.risk_score >= threshold
        ]


def create_bpf_program() -> str:
    """Create the eBPF program source"""
    with open('/home/claude/dhi_kernel.c', 'r') as f:
        return f.read()


def main():
    parser = argparse.ArgumentParser(
        description='Dhi - Runtime Intelligence & Protection System'
    )
    parser.add_argument(
        '--level',
        choices=['log', 'alert', 'block'],
        default='alert',
        help='Protection level (log, alert, or block)'
    )
    parser.add_argument(
        '--whitelist-ip',
        type=str,
        help='Add IP to whitelist (can be used multiple times)'
    )
    parser.add_argument(
        '--whitelist-file',
        type=str,
        help='Add file path to whitelist (can be used multiple times)'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show periodic statistics'
    )
    
    args = parser.parse_args()
    
    # Map protection level
    level_map = {
        'log': ProtectionLevel.LOG_ONLY,
        'alert': ProtectionLevel.ALERT,
        'block': ProtectionLevel.BLOCK
    }
    
    # Load and start protection
    bpf_code = create_bpf_program()
    protector = DhiProtector(bpf_code, level_map[args.level])
    
    # Add whitelists
    if args.whitelist_ip:
        protector.add_whitelist_ip(args.whitelist_ip)
    if args.whitelist_file:
        protector.add_whitelist_file(args.whitelist_file)
        
    # Default whitelists for stability
    protector.add_whitelist_ip('127.0.0.1')
    protector.add_whitelist_ip('169.254.169.254')  # AWS metadata service
    protector.add_whitelist_file('/var/log/')
    protector.add_whitelist_file('/tmp/')
    
    print("=" * 60)
    print("DHI - Runtime Intelligence & Protection System")
    print("धी - Divine Intellect, Modern Security")
    print(f"Protection Level: {args.level.upper()}")
    print("=" * 60)
    print("Monitoring for:")
    print("  • Data exfiltration attempts")
    print("  • Unauthorized file modifications")
    print("  • Suspicious network activity")
    print("=" * 60)
    print("\nPress Ctrl+C to stop monitoring\n")
    
    try:
        protector.start_monitoring()
    except KeyboardInterrupt:
        print("\n\nFinal Statistics:")
        high_risk = protector.get_high_risk_processes(threshold=30)
        if high_risk:
            print(f"\n[!] High-Risk Processes (Risk >= 30):")
            for proc_info in high_risk:
                print(json.dumps(proc_info, indent=2))
        else:
            print("No high-risk processes detected")


if __name__ == '__main__':
    main()
