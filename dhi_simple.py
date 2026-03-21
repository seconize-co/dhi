#!/usr/bin/env python3
"""
Simplified Agent Protection using eBPF
A minimal, easy-to-understand example focusing on core concepts
"""

import ctypes
from bcc import BPF
import sys
import time

# Simplified BPF program - only 150 lines
BPF_CODE = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* Simple event structure */
struct event {
    u32 pid;
    u64 timestamp;
    u32 event_type;  // 1=file_delete, 2=network_send
    u64 data_size;
    char filename[128];
    u32 destination_ip;
};

BPF_RINGBUF_OUTPUT(events, 256);

/* Track file deletions */
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event *e;
    e = (struct event *)bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 1;  // File delete
    
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (void *)args->pathname);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Track large network sends */
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct event *e;
    u64 size = args->len;
    
    // Only track larger transfers to reduce noise
    if (size < 1024)
        return 0;
    
    e = (struct event *)bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 2;  // Network send
    e->data_size = size;
    
    struct sockaddr *addr = (struct sockaddr *)args->addr;
    if (addr) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        bpf_probe_read_kernel(&e->destination_ip,
                              sizeof(u32), &sin->sin_addr.s_addr);
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Track permission changes on sensitive files */
TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    struct event *e;
    u32 mode = args->mode;
    
    // Alert on world-writable (777) or unusual permissions
    if (mode != 0o777 && mode != 0o666 && mode != 0o555)
        return 0;
    
    e = (struct event *)bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 3;  // Permission change
    e->data_size = mode;
    
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (void *)args->filename);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
"""


class SimpleAgentProtector:
    """Minimal agent protection system"""
    
    def __init__(self):
        self.bpf = BPF(text=BPF_CODE)
        self.events_seen = 0
        self.suspicious_pids = {}
        
    def start(self):
        """Start monitoring"""
        print("=" * 60)
        print("SIMPLIFIED AGENT PROTECTION SYSTEM")
        print("=" * 60)
        print("\nMonitoring for:")
        print("  1. File deletions")
        print("  2. Large network sends")
        print("  3. Permission changes")
        print("\nPress Ctrl+C to stop\n")
        
        ringbuf = self.bpf["events"]
        ringbuf.open_ring_buffer(self._process_event)
        
        try:
            while True:
                ringbuf.poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            self._print_summary()
    
    def _process_event(self, cpu, data, size):
        """Handle incoming events"""
        event = self.bpf["events"].event(data)
        self.events_seen += 1
        
        pid = event.pid
        ts = event.timestamp / 1_000_000_000  # Convert to seconds
        event_type = event.event_type
        
        if pid not in self.suspicious_pids:
            self.suspicious_pids[pid] = {
                'count': 0,
                'deletions': 0,
                'network_sends': 0,
                'permission_changes': 0
            }
        
        stats = self.suspicious_pids[pid]
        stats['count'] += 1
        
        if event_type == 1:  # File deletion
            stats['deletions'] += 1
            filename = event.filename.decode('utf-8', errors='ignore').strip('\x00')
            # Alert if sensitive file
            if any(x in filename for x in ['/etc/', '/.ssh/', '/root/', '/home/']):
                print(f"[ALERT] File Deletion - PID {pid}: {filename}")
            else:
                print(f"[INFO] File Delete - PID {pid}: {filename}")
                
        elif event_type == 2:  # Network send
            stats['network_sends'] += 1
            size_mb = event.data_size / (1024 * 1024)
            if event.destination_ip:
                ip = f"{event.destination_ip & 0xFF}.{(event.destination_ip >> 8) & 0xFF}." \
                     f"{(event.destination_ip >> 16) & 0xFF}.{(event.destination_ip >> 24) & 0xFF}"
                if size_mb > 1:
                    print(f"[ALERT] Large Network Send - PID {pid}: {size_mb:.2f}MB to {ip}")
                else:
                    print(f"[INFO] Network Send - PID {pid}: {size_mb:.2f}MB")
            
        elif event_type == 3:  # Permission change
            stats['permission_changes'] += 1
            filename = event.filename.decode('utf-8', errors='ignore').strip('\x00')
            print(f"[ALERT] Permission Change - PID {pid}: {filename} (mode: {oct(event.data_size)})")
    
    def _print_summary(self):
        """Print summary statistics"""
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total Events: {self.events_seen}")
        print(f"Unique PIDs: {len(self.suspicious_pids)}")
        
        if self.suspicious_pids:
            print("\nPID Summary:")
            for pid, stats in sorted(self.suspicious_pids.items()):
                print(f"  PID {pid}: {stats['count']} events "
                      f"(del:{stats['deletions']} "
                      f"net:{stats['network_sends']} "
                      f"chmod:{stats['permission_changes']})")


def main():
    """Entry point"""
    if len(sys.argv) > 1:
        print(__doc__)
        return
    
    protector = SimpleAgentProtector()
    protector.start()


if __name__ == '__main__':
    main()
