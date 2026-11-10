use std::fmt::{Debug, Display, Formatter};

use super::min_max::MinMax;
use crate::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    prev_total_acked: u64,
    acked_time: Option<Instant>,
    prev_acked_time: Option<Instant>,
    total_sent: u64,
    prev_total_sent: u64,
    sent_time: Option<Instant>,
    prev_sent_time: Option<Instant>,
    max_filter: MinMax,
    acked_at_last_window: u64,
}

impl BandwidthEstimation {
    pub(crate) fn on_sent(&mut self, now: Instant, bytes: u64) {
        self.prev_total_sent = self.total_sent;
        self.total_sent += bytes;
        self.prev_sent_time = self.sent_time;
        self.sent_time = Some(now);
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        round: u64,
        app_limited: bool,
    ) {
        self.prev_total_acked = self.total_acked;
        self.total_acked += bytes;
        self.prev_acked_time = self.acked_time;
        self.acked_time = Some(now);

        let prev_sent_time = match self.prev_sent_time {
            Some(prev_sent_time) => prev_sent_time,
            None => return,
        };

        let send_rate = match self.sent_time {
            Some(sent_time) if sent_time > prev_sent_time => Self::bw_from_delta(
                self.total_sent - self.prev_total_sent,
                sent_time - prev_sent_time,
            )
            .unwrap_or(0),
            _ => u64::MAX, // will take the min of send and ack, so this is just a skip
        };

        let ack_rate = match self.prev_acked_time {
            Some(prev_acked_time) => Self::bw_from_delta(
                self.total_acked - self.prev_total_acked,
                now - prev_acked_time,
            )
            .unwrap_or(0),
            None => 0,
        };

        let bandwidth = send_rate.min(ack_rate);
        // A limited application can reveal a higher delivery rate. Lower
        // non-limited samples must also advance the filter's expiry window.
        if bandwidth > 0 && (!app_limited || self.max_filter.get() < bandwidth) {
            self.max_filter.update_max(round, bandwidth);
        }
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.total_acked;
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let b_ns = bytes * 1_000_000_000;
        let bytes_per_second = b_ns / (window_duration_ns as u64);
        Some(bytes_per_second)
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_samples_can_seed_but_cannot_lower_the_estimate() {
        let start = Instant::now();
        let mut estimate = BandwidthEstimation::default();
        estimate.on_sent(start, 1200);
        estimate.on_sent(start + Duration::from_millis(1), 1200);
        estimate.on_ack(start + Duration::from_millis(50), start, 1200, 1, true);
        estimate.on_ack(start + Duration::from_millis(51), start, 1200, 1, true);
        assert_eq!(estimate.get_estimate(), 1_200_000);
        estimate.on_ack(start + Duration::from_millis(61), start, 1200, 100, true);
        assert_eq!(estimate.get_estimate(), 1_200_000);
    }

    #[test]
    fn non_limited_samples_expire_an_old_peak() {
        let start = Instant::now();
        let mut estimate = BandwidthEstimation::default();
        estimate.on_sent(start, 1200);
        estimate.on_sent(start + Duration::from_millis(1), 1200);
        estimate.on_ack(start + Duration::from_millis(50), start, 1200, 1, false);
        estimate.on_ack(start + Duration::from_millis(51), start, 1200, 1, false);
        assert_eq!(estimate.get_estimate(), 1_200_000);
        for round in 2..=30 {
            estimate.on_ack(
                start + Duration::from_millis(51 + (round - 1) * 10),
                start,
                1200,
                round,
                false,
            );
        }
        assert_eq!(estimate.get_estimate(), 120_000);
    }
}
