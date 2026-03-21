// SPDX-License-Identifier: GPL-2.0 OR MIT
//
// Dhi SSL/TLS Interception eBPF Program
// धी - Runtime Security for AI Agents
//
// This program attaches uprobes to SSL library functions to capture
// plaintext data before encryption and after decryption.
//
// Compilation:
//   clang -O2 -g -target bpf -c dhi_ssl.bpf.c -o dhi_ssl.bpf.o
//
// Or using bpf2go:
//   go generate ./...

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum data capture size (16KB - typical TLS record)
#define MAX_DATA_SIZE 16384
// Fixed-size chunk to satisfy strict verifier bounds on helper length args,
// while still carrying enough payload for secret pattern detection.
#define CAPTURE_CHUNK_SIZE 64

// Event direction
#define SSL_WRITE 0
#define SSL_READ 1

// SSL event structure (must match Rust RawSslEvent)
struct ssl_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 timestamp_ns;
    __u64 ssl_ptr;      // SSL* pointer for connection correlation
    __u8 direction;     // 0 = write, 1 = read
    __u32 data_len;
    char comm[16];
    char data[MAX_DATA_SIZE];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} ssl_events SEC(".maps");

// Per-CPU scratch space for building events
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ssl_event);
} ssl_event_scratch SEC(".maps");

// Track active SSL_read calls (to capture data on return)
struct ssl_read_args {
    void *ssl;
    void *buf;
    __u32 num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); // tid
    __type(value, struct ssl_read_args);
} active_ssl_reads SEC(".maps");

// Helper to get event scratch space
static __always_inline struct ssl_event *get_event_scratch() {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&ssl_event_scratch, &zero);
}

// Helper to fill common event fields
static __always_inline void fill_event_common(struct ssl_event *event, void *ssl_ptr, __u8 direction) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)uid_gid;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_ptr = (__u64)ssl_ptr;
    event->direction = direction;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

// Submit event to ring buffer
static __always_inline int submit_ssl_event(struct ssl_event *scratch, void *buf, __u32 len) {
    if (len < CAPTURE_CHUNK_SIZE || len > MAX_DATA_SIZE) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct ssl_event *event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Copy common fields
    __builtin_memcpy(event, scratch, offsetof(struct ssl_event, data));
    
    // Capture data length
    event->data_len = CAPTURE_CHUNK_SIZE;
    
    // Read data from userspace (bounded read)
    __u32 to_read = CAPTURE_CHUNK_SIZE;
    if (bpf_probe_read_user(event->data, to_read, buf) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// OpenSSL / LibreSSL / BoringSSL Probes
// ============================================================================

// int SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/ssl_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, void *buf, int num) {
    struct ssl_event *scratch = get_event_scratch();
    if (!scratch) {
        return 0;
    }
    
    fill_event_common(scratch, ssl, SSL_WRITE);
    if (num <= 0 || num > MAX_DATA_SIZE) {
        return 0;
    }
    return submit_ssl_event(scratch, buf, (__u32)num);
}

// int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
SEC("uprobe/ssl_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex, void *ssl, void *buf, size_t num) {
    struct ssl_event *scratch = get_event_scratch();
    if (!scratch) {
        return 0;
    }
    
    if (num == 0 || num > MAX_DATA_SIZE) {
        return 0;
    }
    fill_event_common(scratch, ssl, SSL_WRITE);
    return submit_ssl_event(scratch, buf, (__u32)num);
}

// int SSL_read(SSL *ssl, void *buf, int num) - entry
// We need to save args and capture data on return
SEC("uprobe/ssl_read")
int BPF_UPROBE(uprobe_ssl_read_entry, void *ssl, void *buf, int num) {
    __u64 tid = bpf_get_current_pid_tgid();
    
    struct ssl_read_args args = {
        .ssl = ssl,
        .buf = buf,
        .num = num,
    };
    
    bpf_map_update_elem(&active_ssl_reads, &tid, &args, BPF_ANY);
    return 0;
}

// SSL_read return - capture the data that was read
SEC("uretprobe/ssl_read")
int BPF_URETPROBE(uretprobe_ssl_read, int ret) {
    if (ret <= 0) {
        return 0; // No data read or error
    }
    
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&active_ssl_reads, &tid);
    if (!args) {
        return 0;
    }
    
    struct ssl_event *scratch = get_event_scratch();
    if (!scratch) {
        bpf_map_delete_elem(&active_ssl_reads, &tid);
        return 0;
    }
    
    if (ret > MAX_DATA_SIZE) {
        bpf_map_delete_elem(&active_ssl_reads, &tid);
        return 0;
    }

    fill_event_common(scratch, args->ssl, SSL_READ);
    submit_ssl_event(scratch, args->buf, (__u32)ret);
    
    bpf_map_delete_elem(&active_ssl_reads, &tid);
    return 0;
}

// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) - entry
SEC("uprobe/ssl_read_ex")
int BPF_UPROBE(uprobe_ssl_read_ex_entry, void *ssl, void *buf, size_t num) {
    __u64 tid = bpf_get_current_pid_tgid();
    
    struct ssl_read_args args = {
        .ssl = ssl,
        .buf = buf,
        .num = num,
    };
    
    bpf_map_update_elem(&active_ssl_reads, &tid, &args, BPF_ANY);
    return 0;
}

// SSL_read_ex return
SEC("uretprobe/ssl_read_ex")
int BPF_URETPROBE(uretprobe_ssl_read_ex, int ret) {
    if (ret != 1) {
        return 0; // SSL_read_ex returns 1 on success
    }
    
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&active_ssl_reads, &tid);
    if (!args) {
        return 0;
    }
    
    struct ssl_event *scratch = get_event_scratch();
    if (!scratch) {
        bpf_map_delete_elem(&active_ssl_reads, &tid);
        return 0;
    }
    
    if (args->num == 0 || args->num > MAX_DATA_SIZE) {
        bpf_map_delete_elem(&active_ssl_reads, &tid);
        return 0;
    }

    fill_event_common(scratch, args->ssl, SSL_READ);
    // For _ex variant, we'd need to read *readbytes, but we use num as an upper bound.
    submit_ssl_event(scratch, args->buf, args->num);
    
    bpf_map_delete_elem(&active_ssl_reads, &tid);
    return 0;
}

// ============================================================================
// GnuTLS Probes
// ============================================================================

// ssize_t gnutls_record_send(gnutls_session_t session, const void *data, size_t data_size)
SEC("uprobe/gnutls_record_send")
int BPF_UPROBE(uprobe_gnutls_send, void *session, void *data, size_t data_size) {
    struct ssl_event *scratch = get_event_scratch();
    if (!scratch) {
        return 0;
    }
    
    if (data_size == 0 || data_size > MAX_DATA_SIZE) {
        return 0;
    }
    fill_event_common(scratch, session, SSL_WRITE);
    return submit_ssl_event(scratch, data, (__u32)data_size);
}

// ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size) - entry
SEC("uprobe/gnutls_record_recv")
int BPF_UPROBE(uprobe_gnutls_recv_entry, void *session, void *data, size_t data_size) {
    __u64 tid = bpf_get_current_pid_tgid();
    
    struct ssl_read_args args = {
        .ssl = session,
        .buf = data,
        .num = data_size,
    };
    
    bpf_map_update_elem(&active_ssl_reads, &tid, &args, BPF_ANY);
    return 0;
}

// gnutls_record_recv return
SEC("uretprobe/gnutls_record_recv")
int BPF_URETPROBE(uretprobe_gnutls_recv, ssize_t ret) {
    if (ret <= 0) {
        return 0;
    }
    
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&active_ssl_reads, &tid);
    if (!args) {
        return 0;
    }
    
    struct ssl_event *scratch = get_event_scratch();
    if (!scratch) {
        bpf_map_delete_elem(&active_ssl_reads, &tid);
        return 0;
    }
    
    __u32 len = (__u32)ret;
    if (len == 0 || len > MAX_DATA_SIZE) {
        bpf_map_delete_elem(&active_ssl_reads, &tid);
        return 0;
    }

    fill_event_common(scratch, args->ssl, SSL_READ);
    submit_ssl_event(scratch, args->buf, len);
    
    bpf_map_delete_elem(&active_ssl_reads, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
