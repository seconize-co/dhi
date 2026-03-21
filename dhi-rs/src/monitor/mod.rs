//! Monitor Module
//!
//! Unified monitoring orchestration.

use anyhow::Result;

/// Monitor configuration
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub enable_ebpf: bool,
    pub enable_agentic: bool,
    pub poll_interval_ms: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enable_ebpf: true,
            enable_agentic: true,
            poll_interval_ms: 100,
        }
    }
}

/// Statistics collector
#[derive(Debug, Default)]
pub struct StatsCollector {
    pub events_processed: u64,
    pub events_per_second: f64,
    pub last_update: Option<std::time::Instant>,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_event(&mut self) {
        self.events_processed += 1;

        // Update events per second
        if let Some(last) = self.last_update {
            let elapsed = last.elapsed().as_secs_f64();
            if elapsed >= 1.0 {
                self.events_per_second = self.events_processed as f64 / elapsed;
                self.events_processed = 0;
                self.last_update = Some(std::time::Instant::now());
            }
        } else {
            self.last_update = Some(std::time::Instant::now());
        }
    }
}
