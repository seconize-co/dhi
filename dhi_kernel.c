#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

/* Data structures for tracking events */
struct file_event {
    u32 pid;
    u64 ts;
    u32 uid;
    char comm[16];
    char filename[256];
    u32 flags;  // O_WRONLY, O_RDONLY, etc.
    u32 mode;
};

struct network_event {
    u32 pid;
    u64 ts;
    u32 uid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 bytes_sent;
    u8 protocol;  // TCP=6, UDP=17
};

struct agent_context {
    u32 pid;
    u32 uid;
    u64 total_bytes_sent;
    u64 total_bytes_received;
    u32 suspicious_connections;
};

/* Ring buffer for events */
BPF_RINGBUF_OUTPUT(events, 256);

/* Hash map: track PIDs and their contexts */
BPF_HASH(agent_contexts, u32, struct agent_context);

/* Hash map: whitelist of allowed files (by inode) */
BPF_HASH(file_whitelist, u64, u8);

/* Hash map: whitelist of allowed network destinations */
BPF_HASH(network_whitelist, u32, u8);

/* Hash map: track file modification attempts */
BPF_HASH(file_modifications, u64, u64);  // inode -> timestamp

/* Configuration thresholds */
BPF_ARRAY(config, u64, 10);
#define CONFIG_MAX_EXFIL_BYTES 0      // Bytes per second threshold
#define CONFIG_SUSPICIOUS_PORT_CHECK 1 // Enable suspicious port detection
#define CONFIG_FILE_WRITE_CHECK 2      // Monitor file writes
#define CONFIG_ENFORCE 3               // Enforce (block) vs just log

/* Helper to get current PID and UID */
static inline u32 get_current_pid_tgid() {
    return bpf_get_current_pid_tgid() & 0xFFFFFFFF;
}

static inline u32 get_current_uid_gid() {
    return bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

/* Trace open/openat syscalls for file access tracking */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = get_current_pid_tgid();
    u32 uid = get_current_uid_gid();
    struct file_event *event;
    
    event = (struct file_event *)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    event->uid = uid;
    event->flags = args->flags;
    event->mode = args->mode;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename),
                              (void *)args->filename);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace write syscalls to detect data exfiltration */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = get_current_pid_tgid();
    u32 uid = get_current_uid_gid();
    u64 fd = args->fd;
    u64 count = args->count;
    
    /* Check if this is a network socket */
    struct file *f = NULL;
    struct socket *sock = NULL;
    
    /* Update agent context with bytes written */
    struct agent_context *ctx;
    ctx = agent_contexts.lookup_or_try_init(&pid, NULL);
    if (ctx) {
        __sync_fetch_and_add(&ctx->total_bytes_sent, count);
    }
    
    return 0;
}

/* Trace sendto/sendmsg syscalls */
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u32 pid = get_current_pid_tgid();
    u32 uid = get_current_uid_gid();
    u64 len = args->len;
    struct sockaddr *addr = (struct sockaddr *)args->addr;
    
    struct network_event *event;
    event = (struct network_event *)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    event->uid = uid;
    event->bytes_sent = len;
    event->protocol = 6; /* TCP - simplified */
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    /* Parse destination address if available */
    if (addr) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        bpf_probe_read_kernel(&event->daddr, sizeof(u32), &sin->sin_addr.s_addr);
        bpf_probe_read_kernel(&event->dport, sizeof(u16), &sin->sin_port);
    }
    
    bpf_ringbuf_submit(event, 0);
    
    /* Check whitelist */
    if (event->daddr) {
        u8 *allowed = network_whitelist.lookup(&event->daddr);
        if (!allowed) {
            __sync_fetch_and_add(&event->pid, 0); /* Flag suspicious */
        }
    }
    
    return 0;
}

/* Trace unlink/unlinkat to detect file deletions */
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    u32 pid = get_current_pid_tgid();
    u32 uid = get_current_uid_gid();
    
    struct file_event *event;
    event = (struct file_event *)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    event->uid = uid;
    event->flags = 0; /* Mark as deletion */
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename),
                              (void *)args->pathname);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace rename operations */
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    u32 pid = get_current_pid_tgid();
    u32 uid = get_current_uid_gid();
    
    struct file_event *event;
    event = (struct file_event *)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    event->uid = uid;
    event->flags = 1; /* Mark as rename */
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename),
                              (void *)args->oldname);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace chmod to detect permission changes */
TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    u32 pid = get_current_pid_tgid();
    u32 uid = get_current_uid_gid();
    
    struct file_event *event;
    event = (struct file_event *)bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    event->uid = uid;
    event->mode = args->mode;
    event->flags = 2; /* Mark as chmod */
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename),
                              (void *)args->filename);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}
